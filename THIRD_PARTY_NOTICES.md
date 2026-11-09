# Third-party dependencies

The first-party applet source, tests, build configuration, and documentation in
this repository are licensed under Apache-2.0. The dependencies below retain
their own licenses. The root LICENSE does not relicense their contents.

Dependencies are obtained through pinned Git submodules or the simulator test
script. The applet CAP and JAR outputs contain this project's applet code;
the Java Card SDK, GlobalPlatform API implementations, build tools, and simulator
are not bundled in those outputs.

| Dependency | Pinned version / revision | Purpose | License and source |
| --- | --- | --- | --- |
| ant-javacard | `0e9ceaa4bb8a52cc1874e4ff1a996bc2edd6906b` (v24.07.30) | Build and verify CAP files | [MIT license](https://github.com/martinpaljak/ant-javacard/blob/0e9ceaa4bb8a52cc1874e4ff1a996bc2edd6906b/LICENSE); Copyright (c) 2015-2024 Martin Paljak |
| Oracle Java Card SDKs | `6025a1d48060b2a72df2d862de310be434f42272` (nested submodule of ant-javacard) | Java Card 3.0.4, 3.0.5u4, and 3.1.0 compiler tools and API exports | Oracle license terms; see the [SDK repository](https://github.com/martinpaljak/oracle_javacard_sdks/tree/6025a1d48060b2a72df2d862de310be434f42272) and each kit's legal notices |
| GlobalPlatform API export files | `13284a6afc8f6ed6905059172645c1e0e175953a` (API 1.6 used for builds) | Compile against the card OS's GlobalPlatform API | [GlobalPlatform License Agreement](https://github.com/OpenJavaCard/globalplatform-exports/blob/13284a6afc8f6ed6905059172645c1e0e175953a/GP-Specification-License-Agreement.pdf); see the [upstream README](https://github.com/OpenJavaCard/globalplatform-exports/blob/13284a6afc8f6ed6905059172645c1e0e175953a/README.md) |
| jCardSim (`com.klinec:jcardsim`) | `3.0.5.11`, SHA-256 verified by `tests/run.sh` | Simulator tests only | Apache-2.0 as declared in the [published POM](https://repo.maven.apache.org/maven2/com/klinec/jcardsim/3.0.5.11/jcardsim-3.0.5.11.pom); retain the artifact's bundled dependency notices if redistributing it |

Before redistributing a dependency, a complete SDK, or a recursive checkout,
review that dependency's applicable license and bundled third-party notices.
In particular, the Oracle SDKs and GlobalPlatform export files are not licensed
under this project's Apache-2.0 license.
