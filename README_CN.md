<div align="center">
   <img src="assets/banner.jpg" width="500" title="VMAware">
   <br>
   <img src="https://img.shields.io/github/actions/workflow/status/NotRequiem/VMAware/build_infrastructure.yml">
   <img src="https://img.shields.io/badge/License-MIT-yellow.svg">
   <br><br>
   <b>VMAware</b> (VM + Aware) 是一个用于虚拟机检测的跨平台 C++ 框架。
   <br><br>
   <a href="README.md">English 🇬🇧</a> | <a href="README_FR.md">Français 🇫🇷</a> | <a href="README_KR.md">한국어 🇰🇷</a> | <a href="README_RU.md">Русский 🇷🇺</a>
</div>

- - -

该库：
- 非常易于使用
- 跨平台（Windows + MacOS + Linux）
- 多架构兼容（alpha, amd64, arm64, arm64ec, armel, armhf, hppa, i386, m68k, mips, mipsel, mips64, mips64el, powerpc, ppc64, ppc64el, riscv64, s390x, sh4, sparc64, x32）
- 配备约90种独特的虚拟机检测技术 [[列表](https://github.com/NotRequiem/VMAware/blob/main/docs/documentation.md#flag-table)]
- 采用最尖端的技术构建
- 能够检测约70种虚拟机品牌，包括 VMware、VirtualBox、QEMU、Hyper-V 等等 [[列表](https://github.com/NotRequiem/VMAware/blob/main/docs/documentation.md#brand-table)]
- 能够击败虚拟机硬化（加固）技术
- 非常灵活，可对执行哪些技术进行细粒度控制
- 能够检测各种虚拟机和半虚拟机技术，包括虚拟机监控程序（Hypervisor）、模拟器、容器、沙箱等
- 具备记忆功能（Memoized），即缓存过往结果并在再次运行时直接获取以提升性能
- 支持 C++11 及以上版本
- 拥有向其他语言（如 Rust、JavaScript 和 Ruby）移植的生态系统支持
- 纯头文件（Header-only）
- 无任何外部依赖
- 完全采用 MIT 许可证，允许不受限制地使用和分发

<br>

## 示例 🧪
```cpp
#include "vmaware.hpp"
#include <iostream>

int main() {
    if (VM::detect()) {
        std::cout << "Virtual machine detected!" << "\n";
    } else {
        std::cout << "Running on bare metal" << "\n";
    }

    std::cout << "VM name: " << VM::brand() << "\n";
    std::cout << "VM type: " << VM::type() << "\n";
    std::cout << "VM certainty: " << (int)VM::percentage() << "%" << "\n";
}
```

可能的输出：
```
Virtual machine detected!
VM name: VirtualBox
VM type: Hypervisor (type 2)
VM certainty: 100%
```

<br>

## 架构 ⚙️

<p align="center">
<img src="assets/vmaware.png" align="center" title="VMAware">
<br>
</p>

<br>

## 命令行工具 🔧
该项目还提供了一个便捷的命令行工具，充分发挥了该库的全部潜力。它同样支持跨平台。

下面是在 Linux 系统上未作任何加固修改的基础 QEMU 系统的示例。

<img src="assets/demo.png" title="cli">

<!-- Try it out on [Compiler Explorer](https://godbolt.org/z/4sKa1sqrW)!-->

<br>

## 安装 📥
要安装此库，请将最新[发布页面](https://github.com/NotRequiem/VMAware/releases/latest)中的 `vmaware.hpp` 文件下载到您的项目中。预编译二进制文件也位于该处。无需 CMake 配置或共享库链接，过程就是这么简单。

但是，如果您想要获取完整项目（通过 `<vmaware.hpp>` 全局访问的头文件以及 CLI 工具），请按照以下命令操作：
```bash
git clone https://github.com/NotRequiem/VMAware 
cd VMAware
```

### 对于 LINUX：
```bash
sudo dnf/apt/yum update -y # 根据您的发行版进行调整
mkdir build
cd build
cmake ..
sudo make install
```

### 对于 MACOS：
```bash
mkdir build
cd build
cmake ..
sudo make install
```

### 对于 WINDOWS：
```bash
cmake -S . -B build/ -G "Visual Studio 16 2019"
```

可选地，您可以通过在 cmake 参数后追加 `-DCMAKE_BUILD_TYPE=Debug` 来创建调试版本。

<br>

### CMake 安装
```cmake
# edit this
set(DIRECTORY "/path/to/your/directory/")

set(DESTINATION "${DIRECTORY}vmaware.hpp")

if (NOT EXISTS ${DESTINATION})
    message(STATUS "Downloading VMAware")
    set(URL "https://github.com/NotRequiem/VMAware/releases/latest/download/vmaware.hpp")
    file(DOWNLOAD ${URL} ${DESTINATION} SHOW_PROGRESS)
else()
    message(STATUS "VMAware already downloaded, skipping")
endif()
```

模块文件及函数版本位于[此处](auxiliary/vmaware_download.cmake)

<br>

## 文档与代码概述 📒
您可以在[此处](docs/documentation.md)查看完整文档。

其中提供了所有细节，如函数、技术、设置和示例。相信我，它并没有那么可怕 ;)

<br>

## 其他语言移植版本 🔀

VMAware 还支持多种语言，如果 C++ 不是您要找的语言，请参考下表。以下所有项目均得到了 VMAware 开发者的官方认可。

| 语言 | 仓库 | 详情 | 作者 |
|:---------|:---------------:|:--------:|:------:|
| <img src="assets/language_icons/8172-ruby-programming-language.webp" width="20"> Ruby | [链接](https://github.com/NotRequiem/VMAware/tree/main/gem) | 嵌入在 VMAware 仓库中的官方 Ruby 移植版本。不支持 Windows。 | [Adam Ruman](https://github.com/addam128) |
| <img src="assets/language_icons/js.png" width="20"> JS | [链接](https://github.com/Kyun-J/node-vm-detect) | 非常优秀的 API，维护活跃。 | [Kyun-J](https://github.com/Kyun-J) |
| <img src="assets/language_icons/rust-logo-512x512.png" width="20"> Rust | [链接](https://github.com/btwmarcel/vmaware-rs) | 非常优秀的 API，经过良好测试，维护活跃 | [Marcel](https://github.com/btwmarcel) |

> [!WARNING]
> 尽管存在非官方移植版本，但与官方版本相比，它们未经充分测试。使用它们需自行承担风险。

<br>

## Q&A ❓

<details>
<summary>它是如何运作的？</summary>
<br>

> 它利用了包含底层和高层反虚拟机技术的综合清单，并计入评分系统。每项技术的评分（0-100）均基于客观标准确定，侧重于通过尽可能减少误报来检测最隐蔽的虚拟机。每项检测到虚拟机的技术都会将其分数累加到单一累计积分中，通过阈值积分来判定它是否确实在虚拟机中运行。

</details>

<details>
<summary>这个库是为谁准备的？有哪些使用场景？</summary>
<br>

> 它专为安全研究人员、虚拟机工程师、反作弊开发者以及几乎任何需要在其项目中部署实用且坚如磐石的虚拟机检测机制的人员而设计。该库对测试虚拟机隐蔽性的恶意软件分析师以及旨在保护其应用程序免遭逆向工程的专有软件开发者非常有用。它是基准测试虚拟机隐藏自身能力免遭检测的有效工具。
> 
> 此外，软件可以根据检测到的环境调整其程序的行为。这对于调试目的很有用，同时系统管理员也可以以不同的方式管理配置。最后，某些应用程序可能希望在法律上通过许可证条款限制在虚拟机中的使用，以防止未经授权的分发或测试。

</details>

<details>
<summary>为什么要做又一个虚拟机检测项目？</summary>
<br>

> 已经有许多具有相同目标的项目，例如 
<a href="https://github.com/CheckPointSW/InviZzzible">InviZzzible</a>、<a href="https://github.com/a0rtega/pafish">pafish</a> 和 <a href="https://github.com/LordNoteworthy/al-khaser">Al-Khaser</a>。与上述项目的不同之处在于，它们没有提供可编程接口来与检测机制进行交互，而且对非 Windows 系统的支持很少甚至没有。此外，所有这些项目中的虚拟机检测通常不够精密，无法切实应用于现实场景。另一个障碍是它们都是 GPL 项目，因此在专有项目中（这类功能的主要受众）使用它们是不可能的。Pafish 和 InviZzzible 已经废弃多年。
> 
> 虽然这些项目在一定程度上对 VMAware 有所帮助，但我们希望做得更好。我们的目标是以跨平台且灵活的方式让检测技术能够通过编程方式访问，以便每个人都能从中获益，而不仅仅是提供一个 CLI 工具。总而言之，这是一个专注于任何场景下实用且逼真的可用性的虚拟机检测框架，旨在提供软件运行环境的最准确结果。

</details>

<details>
<summary>项目开源难道不会让它处于劣势吗？</summary>
<br>

> VMAware 是完全开源的，与闭源相比，这确实让规避者的工作更加容易。但是，我们认为以开放和交互的方式提供尽可能多的虚拟机检测技术是一种值得的权衡。这意味着我们可以通过讨论、协作以及与试图隐藏其存在的反反虚拟机（anti-anti-vm）项目和恶意软件分析工具的竞争，获得宝贵的社区反馈，从而更有效、更准确地增强该库。
> 
> 与闭源相比，所有这些结合在一起，更有成效地进一步推动了虚拟机检测领域的前沿创新。换句话说，这是为了更高的质量和数量、更好的反馈以及更好的开放性，而不是通过混淆来实现安全。这就是为什么 OpenSSH、OpenSSL、Linux 内核和其他基于安全性的软件项目相对安全的原因，因为帮助其改进的人比试图带着恶意探测源代码的人更多。VMAware 秉持这一理念，如果您对安全有所了解，您应该对这句话很熟悉：“通过混淆实现的安全不是真正的安全”。

</details>

<details>
<summary>虚拟机加固（Hardener）对该库的效果如何？</summary>
<br>

> 公开已知的加固工具并不起作用，而且其中大部分在 Windows 上已经被攻破，但这并不意味着该库对它们免疫。我们可能尚未了解的自定义加固工具可能具有理论上的优势，但它们的制作难度要大得多。
> 
> 我们持续跟踪开源和闭源项目以及规避手段以检测它们。Windows 是规避虚拟机检测最常针对的操作系统，因此我们的主要重点是加强该平台的检测能力。
>
> 目前，在 Windows 上没有任何公开的代码仓库、项目或代码库能够完全规避检测。当发现有效的公开规避方法时，通常会在几天内得到修复。我们的军备竞赛主要是针对作弊者用于绕过 VMAware 和反作弊系统的私有保密方法展开的。

</details>

<details>
<summary>它是如何开发的？</summary>
<br>

> 通过研究，我们识别当前用于隐藏虚拟机的方法，并调研能够检测这些方法的通用检测技术。
>
> 一旦我们拥有可投入生产的代码，就会将其上传到本仓库并开始在真实环境中进行实验性测试。任何 GitHub 分支中的所有代码都是实验性的，而最新发布的版本代表我们的稳定代码。
>
> 某些使用我们项目的外部产品在数千台系统上运行我们的库，并与我们合作反馈 VMAware 在这些系统中的表现。所有这些报告都由我们手动检查是否存在误报或一般的任何其他问题。
>
> 在对技术进行评估的同时，我们会根据技术的有效性、可靠性以及它们与其他检测技术的协同运作情况动态调整这些技术的分数。用于制定分数的标准可以在[此处](docs/score_system.md)找到。
>
> 每次向我们的仓库上传新提交时，我们都会使用 GitHub Actions 自动监控我们所针对的每个平台上是否发生编译和运行时问题。
>
> 当我们认为该库积累了足够的更改时，我们就会发布一个版本并在发布说明中详细解释这些更改。在发布之前，我们会进行安全审计以确保新发布的版本是安全的。

</details>

<details>
<summary>将该项目用于恶意软件怎么样？</summary>
<br>

> 出于显而易见的原因，本项目不招揽或鼓励开发恶意软件。即使您打算将其用于隐藏目的，它也很可能会被杀毒软件标记，而且代码本身并未经过任何混淆。
>
> 我们不会刻意开发该库来尝试阻止或规避 EDR 标记，例如使用直接/间接系统调用（syscalling）、内联钩子（inline hook）检测以及与虚拟化检测无关的任何其他类型的恶意软件逃逸技术。

</details>

<details>
<summary>是否计划开发内核模式组件？</summary>
<br>

> 否。在我们看来，目前还没有优秀的针对虚拟机检测的用户模式解决方案，我们希望投入全部时间来满足这一需求。即使完全处于用户模式，我们仍然能够检测到绝大多数隐蔽的虚拟化环境。

</details>

<details>
<summary>它是线程安全的吗？</summary>
<br>

> 否。请勿同时在多个线程中调用该库的函数，我们运行所需的时间不会超过 1 秒。

</details>

<details>
<summary>我在编译时遇到链接错误</summary>
<br>

> 如果您使用 gcc 或 clang 进行编译，请添加 <code>-lm</code> 和 <code>-lstdc++</code> 标志，或者改用 g++/clang++ 编译器。如果您在 Linux 上全新的虚拟机环境中遇到链接器错误，请使用 `sudo apt/dnf/yum update -y` 更新系统以安装所需的 C++ 组件。

</details>

<br>

## 问题、讨论、拉取请求和咨询 📬
如果您有任何建议、想法或任何形式的贡献，欢迎提出！我们非常乐意在 [Issue](https://github.com/NotRequiem/VMAware/issues) 或 [Discussion](https://github.com/NotRequiem/VMAware/discussions) 板块中进行讨论。如果您想私下咨询，请在 Discord 上联系 `shenzken`。

邮件咨询请至：`vmaware.support@gmail.com`

<br>

## 鸣谢、贡献者及致谢 ✒️

<a href="https://github.com/NotRequiem/VMAware/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=NotRequiem/VMAware" />
</a>

<br>

- [Requiem](https://github.com/NotRequiem) (Main developer)
- [kernelwernel](https://github.com/kernelwernel) (Former creator and developer of the project)
- [Check Point Research](https://research.checkpoint.com/)
- [Unprotect Project](https://unprotect.it/)
- [Al-Khaser](https://github.com/LordNoteworthy/al-khaser)
- [pafish](https://github.com/a0rtega/pafish)
- [Matteo Malvica](https://www.matteomalvica.com)
- N. Rin, EP_X0FF
- [Peter Ferrie, Symantec](https://github.com/peterferrie)
- [Graham Sutherland, LRQA Nettitude](https://www.nettitude.com/uk/)
- [Alex](https://github.com/greenozon)
- [Marek Knápek](https://github.com/MarekKnapek)
- [Vladyslav Miachkov](https://github.com/fameowner99)
- [(Offensive Security) Danny Quist](chamuco@gmail.com)
- [(Offensive Security) Val Smith](mvalsmith@metasploit.com)
- Tom Liston + Ed Skoudis
- [Tobias Klein](https://www.trapkit.de/index.html)
- [(S21sec) Alfredo Omella](https://www.s21sec.com/)
- [hfiref0x](https://github.com/hfiref0x)
- [Waleedassar](http://waleedassar.blogspot.com)
- [一半人生](https://github.com/TimelifeCzy)
- [Thomas Roccia (fr0gger)](https://github.com/fr0gger)
- [systemd project](https://github.com/systemd/systemd)
- mrjaxser
- [iMonket](https://github.com/PrimeMonket)
- Eric Parker's discord community 
- [ShellCode33](https://github.com/ShellCode33)
- [Georgii Gennadev (D00Movenok)](https://github.com/D00Movenok)
- [utoshu](https://github.com/utoshu)
- [Jyd](https://github.com/jyd519)
- [git-eternal](https://github.com/git-eternal)
- [dmfrpro](https://github.com/dmfrpro)
- [Teselka](https://github.com/Teselka)
- [Kyun-J](https://github.com/Kyun-J)
- [luukjp](https://github.com/luukjp)
- [Randark](https://github.com/Randark-JMT)
- [Scrut1ny](https://github.com/Scrut1ny)
- [Lorenzo Rizzotti (Dreaming-Codes)](https://github.com/Dreaming-Codes)
- [virtfunc](https://github.com/virtfunc)
- [Adam Ruman](https://github.com/addam128)
- [Juan Diego](https://github.com/w451)
- [Wiisus](https://github.com/wiisus)
- [Marcel](https://github.com/MarcelDev)
- [Max Ufer](https://github.com/Manny684)
- [Everdox](https://github.com/everdox)
- [snackapps](https://github.com/snackapps)
- [Bandwidth](https://github.com/bandw1dth)
- [dano20zombie](https://github.com/dano20zombie)
 
<br>

## 法律声明 📜
您对如何使用本仓库以及确保您的使用符合适用法律、法规以及您所交互的任何第三方系统、服务、账户或数据的条款负全部责任。

本仓库的发布或对任何第三方产品、服务、名称或商标的提及均不暗示任何背书。

本仓库中包含或引用的第三方软件、模型、数据集、二进制文件和其他材料仍受其各自的许可证和条款约束。您有责任查阅并遵守这些单独的条款。


许可证：MIT