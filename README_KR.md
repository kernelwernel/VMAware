<p align="center">
   <img src="assets/banner.jpg" align="center" width="500" title="VMAware">
   <br>
   <img align="center" src="https://img.shields.io/github/actions/workflow/status/kernelwernel/VMAware/cmake-multi-platform.yml">
   <img align="center" src="https://img.shields.io/github/downloads/kernelwernel/VMAware/total">
   <img align="center" src="https://img.shields.io/badge/License-MIT-yellow.svg">
   <a href="https://deepwiki.com/kernelwernel/VMAware"><img align="center" src="https://deepwiki.com/badge.svg" alt="Ask DeepWiki"></a>
   <a href="https://github.com/kernelwernel/VMAware/actions/workflows/code_ql_analysis.yml">
     <img align="center" src="https://github.com/kernelwernel/VMAware/actions/workflows/code_ql_analysis.yml/badge.svg" alt="CodeQL Analysis">
   </a>

   <div align="center">
      <b>VMAware</b> (VM + Aware)는 가상 머신 탐지를 위한 크로스 플랫폼 C++ 라이브러리 입니다.
      <br>
      <br>
      <a href="README.md">English 🇬🇧</a> | <a href="README_CN.md">中文 🇨🇳</a> | <a href="README_FR.md">Français 🇫🇷</a>
   </div>
</p>

- - -

라이브러리 특징:
- 매우 간단한 사용
- 크로스 플랫폼 지원 (Windows + MacOS + Linux)
- 100여개의 가상 머신 감지 기술 [[목록](https://github.com/kernelwernel/VMAware/blob/main/docs/documentation.md#flag-table)]
- 그리고 가장 선구적인 감지 기술
- VMAware, VirtualBox, QEMU, Hyper-V등을 포함하는 70가지 이상의 VM 브랜드 감지 [[목록](https://github.com/kernelwernel/VMAware/blob/main/docs/documentation.md#brand-table)]
- VM 보안 강화 무력화
- x86, ARM 아키텍처 및 32비트 시스템에서도 사용 가능
- 매우 유연한 구조로, 필요한 기술 구현에 세부적인 제어
- 하이퍼바이저, 에뮬레이터, 컨테이너, 샌드박스 등 준 가상 머신 감지
- C++11 이상부터 호환
- 순수 헤더 파일 구현
- 외부 종속성이 없음
- 메모이징 기능으로 이전 결과를 캐싱하여 감지시 성능을 향상
- 이 프로젝트는 MIT 라이선스로 제한 없는 사용, 수정 및 배포가 허용됩니다.

<br>


## 사용 예시 🧪
```cpp
#include "vmaware.hpp"
#include <iostream>

int main() {
    if (VM::detect()) {
        std::cout << "Virtual machine detected!" << "\n";
    } else {
        std::cout << "Running on baremetal" << "\n";
    }

    std::cout << "VM name: " << VM::brand() << "\n";
    std::cout << "VM type: " << VM::type() << "\n";
    std::cout << "VM certainty: " << (int)VM::percentage() << "%" << "\n";
    std::cout << "VM hardening: " << (VM::is_hardened() ? "likely" : "not found") << "\n";
}
```

출력 예시:
```
Virtual machine detected!
VM name: VirtualBox
VM type: Hypervisor (type 2)
VM certainty: 100%
VM hardening: not found
```

<br>

## 라이브러리 구조 ⚙️

<p align="center">
<img src="assets/vmaware.png" align="center" title="VMAware">
<br>
</p>

<br>

## CLI 도구 🔧
이 프로젝트는 라이브러리의 기능을 최대한 활용하기 위해 크로스 플랫폼을 지원하는 CLI 도구도 제공합니다.

아래는 보안 강화 없이 사용하는 리눅스에서의 기본 QEMU 감지 예시입니다.

<img src="assets/demo.png" title="cli">

<!-- Try it out on [Compiler Explorer](https://godbolt.org/z/4sKa1sqrW)!-->

<br>

## 설치 방법 📥
[최신 릴리즈](https://github.com/kernelwernel/VMAware/releases/latest)에서 vmaware.hpp 파일을 다운로드하고, 프로젝트에 추가하세요. 미리 컴파일된 바이너리 파일들도 준비되어 있습니다.  
CMake나 공유 라이브러리 링크 설정이 필요하지 않습니다. 말 그대로 매우 간단합니다.

전체 프로젝트를 포함 시키고자 한다면(즉 전역적으로 vmaware.hpp와 CLI 도구를 사용하고자 한다면), 먼저 이 프로젝트를 가져온다음
```bash
git clone https://github.com/kernelwernel/VMAware 
cd VMAware
```

이후 플랫폼에 따라 다음 커맨드를 사용하세요.

### 리눅스
```bash
sudo dnf/apt/yum update -y # change this to whatever your distro is
mkdir build
cd build
cmake ..
sudo make install
```

### MacOS
```bash
mkdir build
cd build
cmake ..
sudo make install
```

### 윈도우
```bash
cmake -S . -B build/ -G "Visual Studio 16 2019"
```

추가로, CMake 매개변수에 `-DCMAKE_BUILD_TYPE=Debug`를 추가하여 디버그 빌드를 생성할 수 있습니다.

<br>

### CMake 설치
```cmake
# edit this
set(DIRECTORY "/path/to/your/directory/")

set(DESTINATION "${DIRECTORY}vmaware.hpp")

if (NOT EXISTS ${DESTINATION})
    message(STATUS "Downloading VMAware")
    set(URL "https://github.com/kernelwernel/VMAware/releases/latest/download/vmaware.hpp")
    file(DOWNLOAD ${URL} ${DESTINATION} SHOW_PROGRESS)
else()
    message(STATUS "VMAware already downloaded, skipping")
endif()
```
모듈 파일과 함수 버전은 [이곳](auxiliary/vmaware_download.cmake)에 작성되어 있습니다.

<br>

## 문서 및 코드 개요 📒
전체 문서는 [이곳](docs/documentation.md) 에서 확인하실 수 있습니다. 함수, 기술, 설정, 예시가 포함되어 있습니다. 복잡하지 않아요! ;)

이 라이브러리의 아키텍처 및 디자인에 대해 상세히 알고싶으시면, https://deepwiki.com/kernelwernel/VMAware 을 방문하세요

<br>

## Q&A ❓

<details>
<summary>어떻게 동작하나요?</summary>
<br>

> 이 라이브러리는 저수준 및 고수준 기술을 모두 포함하는 포괄적인 안티 VM 탐지 체크리스트를 활용하고, 가중치 할당 메커니즘을 사용합니다. 각 기술의 가중치(0-100)는 오탐(false positive)을 최소화하고 고도로 은밀한 가상 머신 탐지에 집중하도록 설계된 객관적인 기준을 기반으로 합니다. VM을 성공적으로 탐지한 기술에 설정된 가중치가 누적되며, 이 점수가 미리 설정된 임계값을 초과하면 VM 환경으로 판별됩니다.

</details>

<details>
<summary>이 라이브러리는 왜 필요하며 누가 사용 할 수 있나요?</summary>
<br>

> 이 도구는 보안 연구원, 가상 머신 엔지니어, 화이트 해커, 그리고 프로젝트에 실용적이고 강력한 가상 머신 탐지 메커니즘을 구축해야 하는 모든 사용자를 위해 설계되었습니다. 이 라이브러리는 멀웨어 분석가가 가상 머신의 은폐 기능을 테스트하는 데 도움을 주고, 독점 소프트웨어 개발자가 리버스 엔지니어링 공격으로부터 애플리케이션을 보호하는 데 도움을 줍니다. 또한, 가상 머신 은폐 탐지 기능을 평가하는 효과적인 벤치마크 도구 역할을 합니다.
> 
> 또한, 이 소프트웨어는 감지된 환경에 따라 동작을 조정할 수 있습니다. 이는 디버깅 및 테스트 시 매우 유용할 뿐만 아니라 시스템 관리자에게 구성 체계를 유연하게 관리할 수 있는 기능을 제공합니다. 마지막으로, 일부 애플리케이션은 무단 배포 또는 테스트를 방지하기 위해 라이선스 조건을 통해 가상 머신 사용에 대한 법적 제한을 요구할 수 있습니다.
>
> 이 라이브러리는 다른 프로젝트들 에서도 활용되고 있습니다. 대표적으로 고급 멀웨어 분석 프로젝트인 [Hypervisor-Phantom](https://github.com/Scrut1ny/Hypervisor-Phantom)에서 가상 머신 모니터링  환경과 은밀성을 개선하는데 도움을 주었습니다.

</details>

<details>
<summary>다른 가상머신 프로젝트와 다른 점은 무엇인가요?</summary>
<br>

> <a href="https://github.com/CheckPointSW/InviZzzible">InviZzzible</a>, <a href="https://github.com/a0rtega/pafish">pafish</a>, <a href="https://github.com/LordNoteworthy/al-khaser">Al-Khaser</a>와 같은 유사한 프로젝트가 이미 많이 있습니다. 그러나 주요 차이점은 이러한 프로젝트가 탐지 메커니즘을 호출하는 프로그래밍 가능한 인터페이스를 제공하지 않고 윈도우가 아닌 시스템에 대한 지원을 거의 제공하지 않는다는 것입니다. 더 중요한 것은, 이러한 가상 머신 탐지 기술이 종종 정확도가 낮아 실제 상황에 적용하기 어렵고, 지원하는 탐지 기술도 제한적이라는 것입니다. 또 다른 주요 장애물은 이러한 프로젝트가 모두 GPL 라이선스를 따르기 때문에 독점 소프트웨어 프로젝트(이러한 유형의 기능을 주로 사용하는 프로젝트)에서 활용하기에 적합하지 않다는 것입니다. 
>
> Pafish와 InviZzzible 프로젝트는 수년 전부터 중단되었습니다. Al-Khaser는 여전히 간헐적으로 업데이트되고 VMware에서 지원하지 않는 광범위한 탐지 기능(예: 안티 디버깅 및 안티 인젝션)을 제공하지만, 위에서 언급한 다양한 제한 사항으로 인해 실제 성능은 여전히 ​​만족스럽지 않습니다.
> 
> 이러한 프로젝트들이 VMware 개발에 대한 영감을 제공했지만, 저희의 목표는 이러한 프로젝트들을 완전히 뛰어넘는 것입니다. 핵심은 단순히 CLI 도구를 제공하는 것이 아니라, 탐지 기술을 여러 플랫폼에서 프로그래밍 방식으로 유연하게 적용하여 모든 개발자에게 이점을 제공하는 것입니다. 또한, 이 프레임워크는 더욱 광범위한 탐지 기술을 통합하여 모든 시나리오에 대한 실질적인 솔루션을 제공하는 데 중점을 둔 대폭 향상된 가상 머신 탐지 프레임워크를 목표로 하여 제공되고 있습니다.

</details>

<!--
<details>
<summary>How does it compare to paid VM detection libraries?</summary>
<br>

> There are several paid software solutions available for protecting software licenses from reverse engineering or cracking, such as <a href="https://docs.sentinel.thalesgroup.com/home.htm">Thales' Sentinel RMS</a> and <a href="https://vmpsoft.com/">VMProtect</a>. These tools include VM detection as part of their feature set, though their primary focus is not necessarily VM detection unlike this project.
</details>
-->

<details>
<summary>오픈 소스 프로젝트는 라이브러리를 더 취약하게 만들지 않을까요?</summary>
<br>

> VMware의 유일한 단점은 완전히 오픈소스라는 점입니다. 이로 인해 우회 공격자가 사유 소프트웨어에 비해 코드를 분석하기가 더 쉽습니다. 하지만 저희는 이것이 가치 있는 절충안이라고 생각합니다. 수많은 가상 머신 탐지 기술을 개방적이고 상호 보완적인 방식으로 통합하는 것이 코드 난독화에 의존하는 것보다 훨씬 더 가치 있기 때문입니다. 오픈소스는 커뮤니티 토론, 협업 개발, 그리고 가상 머신 탐지 프로젝트 및 악성코드 분석 도구와의 지속적인 협력을 통해 귀중한 피드백을 얻을 수 있음을 의미하며, 이를 통해 탐지 라이브러리를 더욱 효율적이고 정확하게 강화할 수 있습니다.
> 
> 클로즈드 소스 모델과 비교했을 때, 이러한 장점들은 가상 머신 탐지 분야의 최첨단 혁신을 이끌어내 더욱 효율적으로 개발할 수 있도록 합니다. 바로 이러한 이유로 이 프로젝트는 현재 사용 가능한 최고의 가상 머신 탐지 프레임워크가 되었습니다. 다른 감지 프로젝트(오픈 소스 또는 클로즈드 소스)에서는 한 번도 사용하지 않았던 최첨단 혁신 기술을 다수 사용하고 있기 때문에, 이러한 기술을 성공적으로 우회하는 것이 매우 어려운 것으로 입증되었습니다.
>
> 다시 말해, 이는 난독화 기술에 의존하여 보안을 확보하는 것이아니라, 질과 양, 피드백 메커니즘, 그리고 개방성 측면에서 포괄적인 개선을 의미합니다. 이것이 바로 OpenSSH, OpenSSL, Linux 커널과 같은 보안 관련 오픈소스 프로젝트가 상대적으로 보안을 유지할 수 있는 근본적인 이유입니다. 개선에 기여한 참여자의 수가 소스 코드를 악의적으로 탐색하려는 참여자의 수보다 훨씬 많기 때문입니다. VMware는 이러한 철학을 고수하며, 보안 분야에 정통하다면 "난독화를 통해 확보한 보안은 진정한 보안이 아니다"라는 격언을 잘 알고 있을 것입니다.
</details>


<details>
<summary>VM 보안 강화는 이 라이브러리에 얼만큼 효과적일까요?</summary>
<br>

> 알려진 대부분의 공개 강화 도구는 더 이상 효과적이지 않으며, 대부분의 강화 도구가 무력화된 윈도우 플랫폼에서는 더욱 그렇습니다. 그러나 이것이 이 탐지 라이브러리가 완벽하게 효과적 이라는것을 의미하지는 않습니다. 아직 공개되지 않은 맞춤형 강화 도구는 이론적인 이점이 있을 수 있지만, 개발 난이도는 기하급수적으로 증가합니다.

</details>


<details>
<summary>어떻게 개발되나요?</summary>
<br>

> 학술 논문부터 개인 게임 해킹 포럼, Discord 커뮤니티에 이르기까지 다양한 채널을 통한 온라인 연구를 바탕으로, 우리는 가상 머신을 숨기는 데 사용되는 최신 기법을 지속적으로 추적하고 이를 감지할 수 있는 일반적인 솔루션을 연구하여 항상 기술의 선두를 유지합니다.
>
> 프로덕션 퀄리티의 코드 개발을 완료하면 실제 테스트를 위해 개발 브랜치에 업로드합니다. 수백, 수천 대의 장치에서 감지 알고리즘을 실행하고 가상 머신이 감지되면 자동으로 보고한 후, 오탐지에 대한 수동 검증을 수행합니다.
> 
> 실험 테스트와 공개 문서/데이터베이스의 온라인 증거를 토대로 오탐지가 수정된 것으로 확인되면 변경 사항을 메인 브렌치에 병합합니다. 또한 새로운 탐지 기술에 효과성, 신뢰성, 다른 기술과의 시너지 효과 바탕으로 포괄적인 점수를 부여합니다.
>
> 기타 특수한 경우(예: 오탐지, 컴파일 오류, 잠재적 취약점 등)는 즉시 메인 브랜치에 병합됩니다.
>
> 라이브러리 버전에 충분한 개선 사항이 누적되면 릴리즈 되며, 릴리즈 페이지에서 모든 변경 사항을 상세히 기술합니다.

</details>

<details>
<summary>이 프로젝트가 멀웨어로 사용될 수 있을까요?</summary>
<br>

> 당연하게요 이 프로젝트는 멀웨어 개발자를 모집하지 않습니다. 부정적인 목적으로 사용하려고 하더라도, 프로그램 자체가 난독화되어 있지 않기 때문에 바이러스 백신 소프트웨어가 이를 위협으로 표시할 가능성이 매우 높습니다.
>
> 본 라이브러리는 직/간접적으로 시스템 호출이나 인라인 후크 탐지와 같은 악성코드 우회 기법을 사용하는 등 엔드포인트 탐지 및 대응(EDR) 시스템 탐지를 우회하기 위해 의도적으로 개발된 것이 아닙니다. 현재 구현된 모든 기법은 가상 머신 탐지에 중점을 두고 있으며, 악성코드 우회 관련 기능 개발은 포함하지 않습니다.

</details>

<details>
<summary>컴파일시 링크 오류가 발생합니다.</summary>
<br>

> gcc또는 clang을 사용하여 컴파일하는 경우 <code>-lm</code> 혹은 <code>-lstdc++</code> 플래그를 추가하거나, g++/clang++ 컴파일러를 사용하세요. 리눅스의 신규 VM환경에서 링크 오류가 발생하는 경우, 시스템을 업데이트 후 `sudo apt/dnf/yum update -y` 명령어를 통해 필요한 C++구성 요소를 설치하세요.

</details>

<br>

## 이슈, 토론, PR 및 문의 📬
어떤 형태로든 제안, 아이디어 공유, 그리고 기여를 환영합니다! [이슈](https://github.com/kernelwernel/VMAware/issues) 또는 [토론](https://github.com/kernelwernel/VMAware/discussions) 에서 자유롭게 소통하실 수 있으며, 최대한 빠르게 답변 드리고자 노력하고 있습니다. 개인적인 소통은 Discord를 통해 `kr.nl` 혹은 `shenzken` 에게 직접 연락해 주세요.


이메일 연락처: `jeanruyv@gmail.com`

그리고 이 프로젝트가 당신에게 도움이 되었다면, 스타를 부탁드립니다. :)

<br>

## 크레딧, 기여자 및 고마운 분들 ✒️
- [kernelwernel](https://github.com/kernelwernel) (Maintainer and developer)
- [Requiem](https://github.com/NotRequiem) (Maintainer and co-developer)
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

<br>

## 법률 고지 📜
이 프로젝트를 악의적으로 사용하여 발생한 모든 피해에 대해 책임이 없으며 배상 하지 않습니다.

License: MIT
