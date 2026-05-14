[![Issues](https://img.shields.io/github/issues/thewover/donut)](https://github.com/TheWover/donut/issues)
[![Contributors](https://img.shields.io/github/contributors/thewover/donut)](https://github.com/TheWover/donut/graphs/contributors)
[![Stars](https://img.shields.io/github/stars/thewover/donut)](https://github.com/TheWover/donut/stargazers)
[![Forks](https://img.shields.io/github/forks/thewover/donut)](https://github.com/TheWover/donut/network/members)
[![License](https://img.shields.io/github/license/thewover/donut)](https://github.com/TheWover/donut/blob/master/LICENSE)
[![Chat](https://img.shields.io/badge/chat-%23donut-orange)](https://bloodhoundgang.herokuapp.com/)
[![Github All Releases](https://img.shields.io/github/downloads/thewover/donut/total.svg)](http://www.somsubhra.com/github-release-stats/?username=thewover&repository=donut)
[![Twitter URL](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/intent/tweet?original_referer=https://github.com/TheWover/donut&text=%23Donut+An+open-source+shellcode+generator+that+supports+in%2Dmemory+execution+of+VBS%2FJS%2FEXE%2FDLL+files:+https://github.com/TheWover/donut)

![Alt text](https://github.com/TheWover/donut/blob/master/img/donut_logo_white.jpg?raw=true "Donut Logo")

<p>当前版本：<a href="https://github.com/TheWover/donut/releases">v1.1</a></p>

<h2>目录</h2>

<ol>
  <li><a href="#intro">简介</a></li>
  <li><a href="#how">工作原理</a></li>
  <li><a href="#build">构建</a></li>
  <li><a href="#usage">用法</a></li>
  <li><a href="#subproj">子项目</a></li>
  <li><a href="#dev">基于 Donut 开发</a></li>
  <li><a href="#qad">问题与讨论</a></li>
  <li><a href="#disclaimer">免责声明</a></li>
</ol>

<h2 id="intro">1. 简介</h2>

<p><strong>Donut</strong> 是一种位置无关代码（PIC），可在内存中执行 VBScript、JScript、EXE、DLL 文件和 .NET 程序集。由 Donut 生成的模块可以通过 HTTP 服务器分阶段下载，也可以直接嵌入加载器本身。模块可选使用 <a href="https://tinycrypt.wordpress.com/2017/02/20/asmcodes-chaskey-cipher/">Chaskey</a> 分组密码和 128 位随机密钥进行加密。文件在内存中加载并执行后，原始引用会被擦除以阻止内存扫描。生成器和加载器支持以下功能：</p>

<ul>
  <li>使用 aPLib 和 LZNT1、Xpress、Xpress Huffman（通过 RtlCompressBuffer）压缩输入文件。</li>
  <li>使用熵值生成 API 哈希和随机字符串。</li>
  <li>128 位对称加密文件。</li>
  <li>覆盖原生 PE 头。</li>
  <li>以 MEM_IMAGE 内存类型存储原生 PE。</li>
  <li>修补反恶意软件扫描接口（AMSI）和 Windows 锁定策略（WLDP）。</li>
  <li>修补 Windows 事件跟踪（ETW）。</li>
  <li>修补 EXE 文件的命令行。</li>
  <li>修补退出相关 API 以避免终止宿主进程。</li>
  <li>多种输出格式：C、Ruby、Python、PowerShell、Base64、C#、十六进制和 UUID 字符串。</li>
</ul>

<p>提供适用于 Linux 和 Windows 的动态库与静态库，可集成到您自己的项目中。还有一个 Python 模块，详情参见 <a href="https://github.com/TheWover/donut/blob/master/docs/2019-08-21-Python_Extension.md">构建和使用 Python 扩展</a>。</p>

<h2 id="how">2. 工作原理</h2>

<p>Donut 为每种支持的文件类型提供了独立的加载器。对于 .NET EXE/DLL 程序集，Donut 使用非托管 CLR Hosting API 加载公共语言运行时（CLR）。CLR 加载到宿主进程后，会创建一个新的应用程序域以支持在使用后可销毁的 AppDomain 中运行程序集。AppDomain 就绪后，通过 AppDomain.Load_3 方法加载 .NET 程序集。最后，调用 EXE 的入口点或用户指定的 DLL 公共方法并传入附加参数。有关 <a href=" https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/hosting/clr-hosting-interfaces">非托管 CLR Hosting API</a> 的文档，请参阅 MSDN。独立的 CLR Host 示例请参阅<a href="https://github.com/TheWover/donut/blob/master/DonutTest/rundotnet.cpp">此代码</a>。</p>

<p>VBScript 和 JScript 文件通过 IActiveScript 接口执行。同时对 Windows Script Host（wscript/cscript）的部分方法提供了最小支持。独立示例请参阅<a href="https://gist.github.com/odzhan/d18145b9538a3653be2f9a580b53b063">此代码</a>。更详细说明请阅读：<a href="https://modexp.wordpress.com/2019/07/21/inmem-exec-script/">JavaScript、VBScript、JScript 和 XSL 的内存执行</a></p>

<p>非托管原生 EXE/DLL 文件使用自定义 PE 加载器执行，支持延迟导入、TLS 和命令行修补。仅支持包含重定位信息的文件。更多信息请阅读 <a href="https://modexp.wordpress.com/2019/06/24/inmem-exec-dll/">DLL 内存执行</a>。</p>

<p>加载器可以禁用 AMSI 和 WLDP，以帮助规避对内存中执行的恶意文件的检测。更多信息请阅读 <a href="https://modexp.wordpress.com/2019/06/03/disable-amsi-wldp-dotnet/">红队如何绕过 .NET 动态代码的 AMSI 和 WLDP</a>。还支持使用 aPLib 或 RtlDecompressBuffer API 在内存中解压文件。更多信息请阅读 <a href="https://modexp.wordpress.com/2019/12/08/shellcode-compression/">数据压缩</a>。</p>

<p>从 v1.0 开始，ETW 也被绕过。与 AMSI/WLDP 一样，这是一个模块化系统，允许您将默认绕过替换为自己的实现。默认绕过源自 XPN 的研究。更多信息请阅读 <a href="https://blog.xpnsec.com/hiding-your-dotnet-etw/">隐藏你的 .NET - ETW</a>。</p>

<p>默认情况下，加载器将覆盖非托管 PE 的 PE 头（从基址到 <code>IMAGE_OPTIONAL_HEADER.SizeOfHeaders</code>）。如果没有使用诱饵模块（模块重载），PE 头将被清零。如果使用了诱饵模块，诱饵模块的 PE 头将用于覆盖载荷模块的 PE 头。这是为了阻止通过比较内存中的 PE 头与磁盘文件来检测。用户可以要求保留 PE 头的原始状态，这有助于载荷模块需要访问其 PE 头时（如查找嵌入的 PE 资源）。</p>

<p>有关生成器的详细操作指南以及 Donut 如何影响攻击技术，请阅读 <a href="https://thewover.github.io/Introducing-Donut/">Donut - 将 .NET 程序集作为 Shellcode 注入</a>。有关加载器的更多信息，请阅读 <a href="https://modexp.wordpress.com/2019/05/10/dotnet-loader-shellcode/">从内存加载 .NET 程序集</a>。</p>

<p>希望了解更多内部机制的读者请参阅 <a href="https://github.com/TheWover/donut/blob/master/docs/devnotes.md">开发者笔记</a>。</p>

<h2 id="build">3. 构建</h2>

<p>有两种构建类型。如果需要调试 Donut，请参阅<a href="https://github.com/TheWover/donut/blob/master/docs/devnotes.md">此处文档</a>。否则，继续阅读发布版本的构建方法。</p>

<h3><strong>克隆仓库</strong></h3>

<p>从 Windows 命令提示符或 Linux 终端，克隆仓库。</p>

<pre>
  git clone http://github.com/thewover/donut.git
</pre>

<p>下一步取决于您的操作系统和选择的编译器。目前，Donut 的生成器和加载器模板可以使用 Microsoft Visual Studio 2019 和 MingGW-64 成功编译。要将库用于您自己的 C/C++ 项目，请参考<a href="https://github.com/TheWover/donut/tree/master/examples">此处的示例</a>。</p>

<h4><strong>Windows</strong></h4>

<p>要生成加载器模板、动态库 donut.dll、静态库 donut.lib 和生成器 donut.exe，请打开 x64 Microsoft Visual Studio 开发者命令提示符，切换到 Donut 仓库目录，输入以下命令：</p>

<pre>
  nmake -f Makefile.msvc
</pre>

<p>在 Windows 或 Linux 上使用 MinGW-64 完成相同操作，切换到 Donut 仓库目录，输入以下命令：</p>

<pre>
  make -f Makefile.mingw
</pre>

<h4><strong>Linux</strong></h4>

<p>要生成动态库 donut.so、静态库 donut.a 和生成器 donut，切换到 Donut 仓库目录，直接输入 make。</p>

<h3>Python 模块</h3>

<p>Donut 可以作为 Python 模块安装和使用。从源代码安装需要 Python3 的 pip。首先，确保旧版本的 donut-shellcode 没有安装，在 Linux 终端或 Microsoft Visual Studio 命令提示符中执行以下命令。</p>

<pre>
  pip3 uninstall donut-shellcode
</pre>

<p>确认旧版本已卸载后，执行以下命令。</p>

<pre>
  pip3 install .
</pre>

<p>您也可以从 PyPi 仓库安装 Donut Python 模块。</p>

<pre>
  pip3 install donut-shellcode
</pre>

<p>更多信息，请参考 <a href="https://github.com/TheWover/donut/blob/master/docs/2019-08-21-Python_Extension.md">构建和使用 Python 扩展</a>。</p>

<h3>Docker</h3>

<p>构建 Docker 容器。</p>

<pre>
  docker build -t donut .
</pre>

<p>运行 donut。</p>

<pre>
  docker run -it --rm -v "${PWD}:/workdir" donut -h
</pre>

<h3>辅助工具</h3>

<p>Donut 包含几个可单独构建的附加可执行文件：hash.exe、encrypt.exe、inject.exe 和 inject_local.exe。前两者用于 shellcode 生成。后两者用于辅助测试 donut 生成的 shellcode。inject.exe 将通过 PID 或进程名将原始二进制文件（loader.bin）注入到进程中。inject_local.exe 将原始二进制文件注入到自身进程中。</p>

<p>要单独构建这些辅助可执行文件，可以使用 MSVC makefile。例如，要构建 inject_local.exe 来测试您的 donut shellcode：</p>

<pre>
  nmake inject_local -f Makefile.msvc
</pre>

<h3>发布版本</h3>

<p>每个 Donut 发布版本都有对应的标签，包含已编译的可执行文件。</p>

<ul>
  <li><a href="https://github.com/TheWover/donut/releases/tag/v0.9.3">v0.9.3, TBD</a></li>
  <li><a href="https://github.com/TheWover/donut/releases/tag/v0.9.2">v0.9.2, Bear Claw</a></li>
  <li><a href="https://github.com/TheWover/donut/releases/tag/v0.9.1">v0.9.1, Apple Fritter</a></li>
  <li><a href="https://github.com/TheWover/donut/releases/tag/v0.9">v0.9.0, Initial Release</a></li>
</ul>

<p>目前还有两个其他生成器可用。</p>

<ul>
  <li><a href="https://github.com/n1xbyte/donutCS">n1xbyte 的 C# 生成器</a></li>
  <li><a href="https://github.com/Binject/go-donut">awgh 的 Go 生成器</a></li>
</ul>

<h2 id="usage">4. 用法</h2>

<p>下表列出了生成器命令行版本支持的开关。</p>

<table border="1">
  <tr>
    <th>开关</th>
    <th>参数</th>
    <th>说明</th>
  </tr>

  <tr>
    <td><strong>-a</strong></td>
    <td><var>arch</var></td>
    <td>加载器目标架构：1=x86, 2=amd64, 3=x86+amd64（默认）。</td>
  </tr>

  <tr>
    <td><strong>-b</strong></td>
    <td><var>level</var></td>
    <td>绕过 AMSI/WLDP 的行为：1=不绕过, 2=失败时中止, 3=失败时继续（默认）。</td>
  </tr>

  <tr>
    <td><strong>-k</strong></td>
    <td><var>headers</var></td>
    <td>保留 PE 头：1=覆盖（默认）, 2=保留全部。</td>
  </tr>

  <tr>
    <td><strong>-j</strong></td>
    <td><var>decoy</var></td>
    <td>可选的诱饵模块路径，用于模块重载。</td>
  </tr>

  <tr>
    <td><strong>-c</strong></td>
    <td><var>class</var></td>
    <td>可选的类名（.NET DLL 必需）。可包含命名空间，如 <em>namespace.class</em></td>
  </tr>

  <tr>
    <td><strong>-d</strong></td>
    <td><var>name</var></td>
    <td>为 .NET 创建的 AppDomain 名称。如果启用了熵，则随机生成一个。</td>
  </tr>

  <tr>
    <td><strong>-e</strong></td>
    <td><var>level</var></td>
    <td>熵级别：1=无, 2=生成随机名称, 3=生成随机名称 + 使用对称加密（默认）。</td>
  </tr>

  <tr>
    <td><strong>-f</strong></td>
    <td><var>format</var></td>
    <td>保存到文件的加载器输出格式：1=二进制（默认）, 2=Base64, 3=C, 4=Ruby, 5=Python, 6=PowerShell, 7=C#, 8=十六进制。</td>
  </tr>

  <tr>
    <td><strong>-m</strong></td>
    <td><var>name</var></td>
    <td>可选的 DLL 方法或函数（.NET DLL 需要方法）。</td>
  </tr>

  <tr>
    <td><strong>-n</strong></td>
    <td><var>name</var></td>
    <td>HTTP 分阶段的模块名称。如果启用了熵，则随机生成一个。</td>
  </tr>

  <tr>
    <td><strong>-o</strong></td>
    <td><var>path</var></td>
    <td>指定 Donut 保存加载器的位置。默认为当前目录的 loader.bin。</td>
  </tr>

  <tr>
    <td><strong>-p</strong></td>
    <td><var>parameters</var></td>
    <td>可选的参数/命令行，在引号内传递给 DLL 方法/函数或 EXE。</td>
  </tr>

  <tr>
    <td><strong>-r</strong></td>
    <td><var>version</var></td>
    <td>CLR 运行时版本。默认使用 MetaHeader，如果没有则使用 v4.0.30319。</td>
  </tr>

  <tr>
    <td><strong>-s</strong></td>
    <td><var>server</var></td>
    <td>托管 Donut 模块的 HTTP 服务器 URL。可以按以下格式提供凭据：<pre>https://username:password@192.168.0.1/</pre></td>
  </tr>

  <tr>
    <td><strong>-t</strong></td>
    <td></td>
    <td>以线程方式运行非托管/原生 EXE 的入口点，并等待线程结束。</td>
  </tr>

  <tr>
    <td><strong>-w</strong></td>
    <td></td>
    <td>以 UNICODE 格式传递命令行给非托管 DLL 函数（默认为 ANSI）。</td>
  </tr>

  <tr>
    <td><strong>-x</strong></td>
    <td><var>option</var></td>
    <td>决定加载器如何退出：1=退出线程（默认）, 2=退出进程, 3=不退出也不清理，无限阻塞。</td>
  </tr>

  <tr>
    <td><strong>-y</strong></td>
    <td><var>addr</var></td>
    <td>为加载器创建新线程，并在相对于宿主进程可执行文件偏移的地址处继续执行。提供的值是偏移量。此选项支持加载器在 donut 执行完成后恢复宿主进程的执行。</td>
  </tr>

  <tr>
    <td><strong>-z</strong></td>
    <td><var>engine</var></td>
    <td>打包/压缩输入文件：1=无, 2=aPLib, 3=LZNT1, 4=Xpress, 5=Xpress Huffman。目前后三种仅在 Windows 上受支持。</td>
  </tr>
</table>

<h3 id="requirements">载荷要求</h2>

<p>为了使 Donut 成功加载，您的载荷必须满足一些特定要求。</p>

<h3 id="requirements-dotnet">.NET 程序集</h2>

<ul>
  <li>入口点方法必须只接受字符串参数，或不接受任何参数。</li>
  <li>入口点方法必须标记为 public 和 static。</li>
  <li>包含入口点方法的类必须标记为 public。</li>
  <li>程序集不能是混合程序集（同时包含托管和原生代码）。</li>
  <li>因此，程序集不能包含任何非托管导出。</li>
</ul>

<h3 id="requirements-native">原生 EXE/DLL</h2>

<ul>
  <li>不支持使用 Cygwin 構建的二進制文件。</li>
</ul>

<p>Cygwin 可执行文件使用的初始化例程期望宿主进程从磁盘运行。如果从内存执行，宿主进程可能会崩溃。</p>

<h3 id="requirements-dotnet">非托管 DLL</h2>

<ul>
  <li>用户指定的入口点方法必须只接受一个字符串参数，或不接受任何参数。我们提供了一个<a href="https://github.com/TheWover/donut/blob/master/DonutTest/dlltest.c/">示例</a>。</li>
</ul>

<h2 id="subproj">5. 子项目</h2>

<p>Donut 提供了四个配套项目：</p>

<table border="1">
  <tr>
    <th>工具</th>
    <th>说明</th>
  </tr>
  <tr>
    <td>DemoCreateProcess</td>
    <td>用于测试的示例 .NET 程序集。接受两个命令行参数，每个参数指定要执行的程序。</td>
  </tr>
  <tr>
    <td>DonutTest</td>
    <td>用于测试 donut 的简单 C# shellcode 注入器。shellcode 必须进行 Base64 编码并以字符串形式复制进来。</td>
  </tr>
  <tr>
    <td>ModuleMonitor</td>
    <td>概念验证工具，检测由 Donut 和 Cobalt Strike 的 execute-assembly 等工具执行的 CLR 注入。</td>
  </tr>
  <tr>
    <td>ProcessManager</td>
    <td>进程发现工具，攻击方可用于确定注入目标，防御方可用于确定正在运行的内容、这些进程的属性以及它们是否加载了 CLR。</td>
  </tr>
</table>

<h2 id="dev">6. 基于 Donut 开发</h2>

<p>您可能希望添加对更多载荷类型的支持、更改功能集或将 Donut 集成到现有工具中。我们提供了<a href="https://github.com/TheWover/donut/blob/master/docs/devnotes.md">开发者文档</a>。其他功能留作读者练习。我们的建议：</p>

<ul>
  <li>添加环境密钥。</li>
  <li>通过在每次生成 shellcode 时混淆加载器，使 Donut 具有多态性。</li>
  <li>将 Donut 作为模块集成到您喜欢的 RAT/C2 框架中。</li>
</ul>

<h2 id="qad">7. 问题与讨论</h2>

<p>如果您对 Donut 有任何问题或意见，请加入 <a href="https://bloodhoundgang.herokuapp.com/">BloodHound Gang Slack</a> 中的 #Donut 频道。</p>

<h2 id="disclaimer">8. 免责声明</h2>

<p>我们不对本软件或技术的任何滥用负责。Donut 作为 CLR 注入和通过 shellcode 进行内存加载的演示提供，旨在为红队人员提供一种模拟对手的方式，并为防御者提供构建分析和缓解措施的参考框架。这不可避免地带来了恶意软件作者和威胁行为者滥用它的风险。然而，我们相信净收益超过风险。希望如此。如果 EDR 或 AV 产品能够通过签名或行为模式检测到 Donut，我们将不会更新 Donut 来对抗签名或检测方法。为了避免冒犯，请不要提出此类要求。</p>
