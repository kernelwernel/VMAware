<div align="center">
   <img src="assets/banner.jpg" width="500" title="VMAware">
   <br>
   <img src="https://img.shields.io/github/actions/workflow/status/NotRequiem/VMAware/build_infrastructure.yml">
   <img src="https://img.shields.io/badge/License-MIT-yellow.svg">
   <br><br>
   <b>VMAware</b> (VM + Aware) est un framework C++ multiplateforme pour la détection de machines virtuelles.
   <br><br>
   <a href="README.md">English 🇬🇧</a> | <a href="README_CN.md">中文 🇨🇳</a> | <a href="README_KR.md">한국어 🇰🇷</a> | <a href="README_RU.md">Русский 🇷🇺</a>
</div>

- - -

La bibliothèque est :
- Très facile à utiliser
- Multiplateforme (Windows + MacOS + Linux)
- Compatible multi-architectures (alpha, amd64, arm64, arm64ec, armel, armhf, hppa, i386, m68k, mips, mipsel, mips64, mips64el, powerpc, ppc64, ppc64el, riscv64, s390x, sh4, sparc64, x32)
- Équipée d'environ 90 techniques uniques de détection de VM [[liste](https://github.com/NotRequiem/VMAware/blob/main/docs/documentation.md#flag-table)]
- Conçue avec les techniques les plus avancées
- Capable de détecter environ 70 marques de VM, notamment VMware, VirtualBox, QEMU, Hyper-V et bien d'autres [[liste](https://github.com/NotRequiem/VMAware/blob/main/docs/documentation.md#brand-table)]
- Capable de contourner les renforts (hardeners) de VM
- Très flexible, avec un contrôle précis des techniques exécutées
- Capable de détecter diverses technologies de VM et semi-VM, notamment les hyperviseurs, émulateurs, conteneurs, sandboxes, etc.
- Mémoïsée, ce qui signifie que les résultats passés sont mis en cache et récupérés en cas de nouvelle exécution pour des gains de performances
- Disponible avec C++11 et versions ultérieures
- Soutenue par un écosystème de portages vers d'autres langages tels que Rust, JavaScript et Ruby
- Header-only (composée uniquement de fichiers d'en-tête)
- Sans aucune dépendance externe
- Entièrement sous licence MIT, permettant une utilisation et une distribution sans restriction

<br>

## Exemple 🧪
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

Résultat possible :
```
Virtual machine detected!
VM name: VirtualBox
VM type: Hypervisor (type 2)
VM certainty: 100%
```

<br>

## Structure ⚙️

<p align="center">
<img src="assets/vmaware.png" align="center" title="VMAware">
<br>
</p>

<br>

## Outil CLI 🔧
Ce projet fournit également un outil CLI pratique exploitant tout le potentiel de la bibliothèque. Il offre également une prise en charge multiplateforme.

Vous trouverez ci-dessous un exemple d'un système QEMU de base sans modifications de renforcement sur Linux.

<img src="assets/demo.png" title="cli">

<!-- Try it out on [Compiler Explorer](https://godbolt.org/z/4sKa1sqrW)!-->

<br>

## Installation 📥
Pour installer la bibliothèque, téléchargez le fichier `vmaware.hpp` dans la dernière [section des releases](https://github.com/NotRequiem/VMAware/releases/latest) vers votre projet. Les binaires s'y trouvent également. Aucun CMake ni liaison d'objets partagés n'est nécessaire, c'est aussi simple que cela.

Toutefois, si vous souhaitez obtenir le projet complet (fichiers d'en-tête accessibles globalement avec `<vmaware.hpp>` et l'outil CLI), suivez ces commandes :
```bash
git clone https://github.com/NotRequiem/VMAware 
cd VMAware
```

### POUR LINUX :
```bash
sudo dnf/apt/yum update -y # modifiez ceci en fonction de votre distribution
mkdir build
cd build
cmake ..
sudo make install
```

### POUR MACOS :
```bash
mkdir build
cd build
cmake ..
sudo make install
```

### POUR WINDOWS :
```bash
cmake -S . -B build/ -G "Visual Studio 16 2019"
```

Optionnellement, vous pouvez créer une version de débogage en ajoutant `-DCMAKE_BUILD_TYPE=Debug` aux arguments cmake.

<br>

### Installation avec CMake
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

Le fichier de module et la version fonctionnelle se trouvent [ici](auxiliary/vmaware_download.cmake)

<br>

## Documentation et aperçu du code 📒
Vous pouvez consulter la documentation complète [ici](docs/documentation.md). 

Tous les détails tels que les fonctions, les techniques, les paramètres et les exemples y sont fournis. Croyez-moi, ce n'est pas si intimidant ;)

<br>

## Portages vers d'autres langages 🔀

VMAware prend également en charge une variété de langages. Si C++ n'est pas le langage que vous recherchez, veuillez vous référer à la liste ci-dessous. Tous ces projets sont officiellement référencés par les développeurs de VMAware.

| Langage | Dépôt | Détails | Auteur |
|:---------|:---------------:|:--------:|:------:|
| <img src="assets/language_icons/8172-ruby-programming-language.webp" width="20"> Ruby | [lien](https://github.com/NotRequiem/VMAware/tree/main/gem) | Portage Ruby officiel intégré dans le dépôt VMAware. Windows n'est pas pris en charge. | [Adam Ruman](https://github.com/addam128) |
| <img src="assets/language_icons/js.png" width="20"> JS | [lien](https://github.com/Kyun-J/node-vm-detect) | Très bonne API, activement maintenue. | [Kyun-J](https://github.com/Kyun-J) |
| <img src="assets/language_icons/rust-logo-512x512.png" width="20"> Rust | [lien](https://github.com/btwmarcel/vmaware-rs) | Très bonne API, bien testée, activement maintenue | [Marcel](https://github.com/btwmarcel) |

> [!WARNING]
> Bien que des portages non officiels existent, ils ne sont pas testés par rapport à nos portages officiels. Utilisez-les à vos propres risques.

<br>

## Q&A ❓

<details>
<summary>Comment ça marche ?</summary>
<br>

> Il utilise une liste exhaustive de techniques anti-VM de bas et de haut niveau qui sont prises en compte dans un système de score. Les scores (0 à 100) de chaque technique sont attribués sur la base de critères objectifs visant à détecter les VM les plus furtives tout en minimisant les faux positifs au maximum. Chaque technique ayant détecté une VM voit son score ajouté à un total cumulé unique, où un seuil de points détermine si l'exécution a réellement lieu dans une VM.

</details>

<details>
<summary>À qui s'adresse cette bibliothèque et quels sont ses cas d'utilisation ?</summary>
<br>

> Elle est conçue pour les chercheurs en sécurité, les ingénieurs en virtualisation, les développeurs d'anti-triche et toute personne ayant besoin d'un mécanisme de détection de VM pratique et solide dans son projet. La bibliothèque est utile aux analystes de logiciels malveillants testant la dissimulation de leurs VM et aux développeurs de logiciels propriétaires souhaitant protéger leurs applications contre l'ingénierie inverse. C'est un outil efficace pour évaluer la capacité d'une VM à se dissimuler face à la détection.
> 
> De plus, les logiciels peuvent adapter le comportement de leur programme en fonction de l'environnement détecté. Cela peut être utile à des fins de débogage, tandis que les administrateurs système peuvent gérer les configurations différemment. Enfin, certaines applications peuvent souhaiter restreindre légalement l'utilisation dans des VM via une clause de licence afin d'empêcher la distribution ou les tests non autorisés.

</details>

<details>
<summary>Pourquoi un autre projet de détection de VM ?</summary>
<br>

> De nombreux projets poursuivent déjà le même objectif, tels que 
<a href="https://github.com/CheckPointSW/InviZzzible">InviZzzible</a>, <a href="https://github.com/a0rtega/pafish">pafish</a> et <a href="https://github.com/LordNoteworthy/al-khaser">Al-Khaser</a>. La différence avec les projets susmentionnés est qu'ils ne fournissent pas d'interface programmable pour interagir avec les mécanismes de détection, en plus d'offrir peu ou pas de support pour les systèmes non-Windows. De plus, les détections de VM dans tous ces projets ne sont souvent pas assez sophistiquées pour être appliquées de manière pratique dans des scénarios réels. Un obstacle supplémentaire est qu'ils sont tous sous licence GPL, leur utilisation dans des projets propriétaires (qui constituent le public principal d'une telle fonctionnalité) est donc hors de question. Pafish et InviZzzible sont abandonnés depuis des années.
> 
> Bien que ces projets aient été utiles à VMAware dans une certaine mesure, nous voulions faire bien mieux. Notre objectif était de rendre les techniques de détection accessibles par programmation d'une manière multiplateforme et flexible afin que chacun puisse en tirer quelque chose d'utile, plutôt que de fournir un simple outil CLI. En résumé, il s'agit d'un framework de détection de VM axé sur une utilisation pratique et réaliste pour tout scénario, visant à fournir le résultat le plus précis de l'environnement dans lequel votre logiciel s'exécute.

</details>

<details>
<summary>Le projet n'est-il pas désavantagé par le fait d'être open source ?</summary>
<br>

> VMAware est entièrement open source, ce qui facilite la tâche des personnes cherchant à le contourner par rapport à un code source fermé. Cependant, nous soutenons qu'il s'agit d'un compromis valable pour disposer d'un maximum de techniques de détection de VM de manière ouverte et interactive. Cela signifie que nous pouvons bénéficier de précieux retours de la communauté pour renforcer la bibliothèque plus efficacement et plus précisément grâce aux discussions, collaborations et à la concurrence face aux projets anti-anti-VM et aux outils d'analyse de malwares qui tentent de masquer leur présence.
> 
> Tout cela combiné a permis de faire progresser les innovations de pointe dans le domaine de la détection de VM de manière bien plus productive que si le code était fermé. En d'autres termes, il s'agit d'une meilleure qualité ET quantité, de meilleurs retours et d'une plus grande ouverture plutôt que de la sécurité par l'obscurité. C'est la même raison pour laquelle OpenSSH, OpenSSL, le noyau Linux et d'autres projets logiciels axés sur la sécurité sont relativement sécurisés : il y a plus de personnes qui aident à les améliorer que de personnes qui tentent de sonder le code source avec des intentions malveillantes. VMAware partage cette philosophie, et si vous connaissez quoi que ce soit à la sécurité, vous devez être familier avec l'adage : « La sécurité par l'obscurité n'est PAS de la sécurité ».

</details>

<details>
<summary>Quelle est l'efficacité des renforts (hardeners) de VM face à la bibliothèque ?</summary>
<br>

> Les renforts publiquement connus ne sont pas efficaces et la plupart d'entre eux sur Windows ont été vaincus, mais cela ne signifie pas que la bibliothèque y est immunisée. Les renforts personnalisés dont nous n'avons peut-être pas connaissance pourraient avoir un avantage théorique, mais ils sont considérablement plus difficiles à concevoir.
> 
> Nous suivons en permanence les projets et contournements open source et closed source afin de les détecter. Windows étant le système d'exploitation le plus ciblé pour contourner les détections de VM, notre priorité absolue est de renforcer les détections sur cette plateforme.
>
> Actuellement, aucun dépôt public, projet ou base de code en général n'est capable de contourner complètement la détection sur Windows. Lorsqu'un contournement public fonctionnel est découvert, il est généralement corrigé en quelques jours. Notre course aux armements est principalement menée contre des méthodes privées gardées secrètes par des tricheurs pour contourner à la fois VMAware et les systèmes anti-triche.

</details>

<details>
<summary>Comment est-il développé ?</summary>
<br>

> Grâce à nos recherches, nous identifions les méthodes actuellement utilisées pour masquer les VM et étudions des techniques de détection génériques capables de repérer ces méthodes.
>
> Dès que nous disposons d'un code prêt pour la production, nous le téléversons sur ce dépôt et commençons les tests expérimentaux dans des environnements réels. Tout le code présent sur n'importe quelle branche GitHub est expérimental, tandis que la dernière version (release) représente notre code stable.
>
> Certains produits qui utilisent notre projet exécutent notre bibliothèque sur des milliers de systèmes, collaborant avec nous pour rapporter le comportement de VMAware sur ces systèmes. Tous ces rapports sont vérifiés manuellement par nos soins pour détecter les faux positifs ou tout autre problème en général.
>
> Lors de l'évaluation des techniques, les scores qui leur sont attribués sont ajustés dynamiquement en fonction de leur efficacité, de leur fiabilité et de leur synergie avec d'autres techniques de détection. Les critères utilisés pour attribuer nos scores sont consultables [ici](docs/score_system.md).
>
> À l'aide de GitHub Actions, nous surveillons automatiquement si des problèmes de compilation et d'exécution surviennent sur chaque plateforme ciblée, à chaque fois qu'un nouveau commit est mis en ligne sur notre dépôt.
>
> Lorsque la bibliothèque a accumulé suffisamment de modifications à nos yeux, nous publions une version et expliquons ces changements en détail. Avant chaque publication, nous réalisons un audit de sécurité pour nous assurer que la nouvelle version publiée est sûre.

</details>

<details>
<summary>Qu'en est-il d'une utilisation pour des logiciels malveillants ?</summary>
<br>

> Ce projet n'encourage en aucun cas le développement de logiciels malveillants pour des raisons évidentes. Même si vous avez l'intention de l'utiliser à des fins de dissimulation, il sera très probablement signalé par les antivirus de toute façon, et rien n'est obfusqué au départ.
>
> Nous ne développons pas intentionnellement la bibliothèque pour tenter de stopper ou d'éviter les alertes EDR, par exemple en utilisant des appels système (syscalls) directs/indirects, la détection d'inline hooking ou tout autre type de technique d'évasion de malware non liée à la détection de virtualisation.

</details>

<details>
<summary>Un composant en mode noyau est-il prévu ?</summary>
<br>

> Non. Selon nous, il n'existe pas de bonnes solutions en mode utilisateur pour la détection de VM, et nous souhaitons consacrer tout notre temps à répondre à cette demande. Nous pouvons toujours détecter les environnements virtualisés les plus furtifs tout en restant entièrement en mode utilisateur. 

</details>

<details>
<summary>Est-elle thread-safe ?</summary>
<br>

> Non. N'appelez pas les fonctions de cette bibliothèque simultanément avec plusieurs threads, notre exécution ne prend pas plus d'une seconde.

</details>

<details>
<summary>J'ai des erreurs d'édition de liens lors de la compilation</summary>
<br>

> Si vous compilez avec gcc ou clang, ajoutez les options <code>-lm</code> et <code>-lstdc++</code>, ou utilisez plutôt les compilateurs g++/clang++. Si vous recevez des erreurs de l'éditeur de liens dans un environnement VM tout neuf sur Linux, mettez à jour votre système avec `sudo apt/dnf/yum update -y` pour installer les composants C++ nécessaires.

</details>

<br>

## Problèmes, discussions, demandes de tirage (pull requests) et demandes de renseignements 📬
Si vous avez des suggestions, des idées ou toute forme de contribution, n'hésitez pas à nous en faire part ! Je serai ravi d'en discuter dans les sections [issues](https://github.com/NotRequiem/VMAware/issues) ou [discussions](https://github.com/NotRequiem/VMAware/discussions). Si vous souhaitez poser une question en privé, contactez `shenzken` sur Discord.

Pour les demandes par e-mail : `vmaware.support@gmail.com`

<br>

## Crédits, contributeurs et remerciements ✒️

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

## Mentions légales 📜
Vous êtes seul responsable de la manière dont vous utilisez ce dépôt et de vous assurer que votre utilisation est conforme aux lois, réglementations applicables ainsi qu'aux conditions de tous les systèmes, services, comptes ou données tiers avec lesquels vous interagissez.

Aucune approbation n'est implicite du fait de la publication de ce dépôt ou de toute référence à des produits, services, noms ou marques de tiers.

Les logiciels, modèles, ensembles de données, binaires et autres matériels tiers inclus ou référencés dans ce dépôt restent soumis à leurs propres licences et conditions. Vous êtes responsable de l'examen et du respect de ces conditions distinctes.


Licence : MIT