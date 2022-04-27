<div align="center">
  <a href="https://github.com/appalaszynski/mac-setup">
    <img src="docs/apple.jpg" width="125px">
  </a>
  <br>
  <h1>Mac Setup Script</h1>
  <emphasis> Designed to quickly bootstrap new Macs by executing a single command to configure Git, Homebrew, Visual Studio Code, Zsh, Fish and corporate proxy settings</emphasis>
</div>

<!-- omit in toc -->
## TOC

- [Features](#features)
- [Setup](#setup)
  - [`MacOS`](#macos)
  - [Usage](#usage)
  - [`ZSH` _(optional)_](#zsh-optional)
  - [`Visual Studio Code` _(optional)_](#visual-studio-code-optional)
- [iTerm2](#iterm2)
- [Git](#git)
- [Chrome](#chrome)
  - [Extensions](#extensions)
- [MacOS Links](#macos-links)
- [FAQ](#faq)
  - [Override default settings](#override-default-settings)
  - [Useful Links](#useful-links)
<!-- omit in toc -->

## Features
- Installs Brew along with formulas in `~/.homebrew`
- Installs support for Zsh
- Installs helper functions for Zsh
- Installs useful Visual Studio Code plugins _(optional)_ - If not installed, the symlink setup will be ignored which means users won't be able to run from `code` command from their shell to open VS Code. Setting the environment variable `VSCODE_BIN_PATH` allows VS Code to be installed in alternate location.
- Creates workspace folder in `~./Workspaces`
- Installs additional Quicklook plugins

## Setup

### `MacOS`

- Install Xcode and iTerm2
- **Option 1**:
  - `git clone https://github.com/tbennett6421/MBP-Setup.git`
  - Run `cd MBP-Setup`
  - Run `chmod +x *.sh`
  - Run `./setup.sh`. This will take a really long time as [Homebrew](https://brew.sh/) installs and compiles a ton of packages.
- **Option 2**:
  - Run `curl *Ls -su $USER https://github.com/tbennett6421/MBP-Setup.git/raw/bootstrap.sh?at=refs%2Fheads%2Fmaster | bash -s` and enter your network password when prompted
- Follow the prompts
- Once setup completes, close the shell and open a new one (or reload current shell)

### Usage

```sh
❯ sh ./setup.sh -h
Usage:
    setup.sh -h                 Show help
    setup.sh -c                 Copy setup files to home folder instead of using symlink
```

### `ZSH` _(optional)_

- After running `./setup.sh`, run `./setup-zsh.sh` (If you receive an error 'pyenv' is not found open a new shell and run `./setup-zsh.sh`)
- Set your terminal to run the Homebrew ZSH. Set [iTerm instructions below](#iterm2).

ZSH uses [oh-my-zsh](https://github.com/robbyrussell/oh-my-zsh) to manage zsh configurations and plugins.

### `Visual Studio Code` _(optional)_

- run `./setup-vscode.sh`

## iTerm2

- Try a theme:
  - [Material Theme](https://github.com/MartinSeeler/iterm2-material-design),
  - [Snazzy Theme](https://github.com/sindresorhus/iterm2-snazzy)
  - [base16-iterm2](https://github.com/chriskempson/base16-iterm2)
  - [Relaxed](https://github.com/mischah/Relaxed)
- Install font that was patched with Glyphs
  - [Powerline Font](https://github.com/powerline/fonts)
  - [Nerd Fonts](https://github.com/ryanoasis/nerd-fonts). Nerd fonts can be installed via Homebrew. Ex: `brew cask install font-fira-mono-nerd-font`

## Git

- [Git Delta](https://github.com/dandavison/delta)
- [Why You Should Use git pull –ff-only](https://blog.sffc.xyz/post/185195398930/why-you-should-use-git-pull-ff-only)

## Chrome

### Extensions

- [Refined Github](https://github.com/sindresorhus/refined-github)
- [Wide Github](https://github.com/xthexder/wide-github)
- [GitHub File Icon](https://github.com/homerchen19/github-file-icon)
- [Github Color Status](https://chrome.google.com/webstore/detail/github-add-color-to-recen/gnlanakllhhldoneeennbednopiaadld)
- [Octolinker](https://github.com/OctoLinker/OctoLinker)
- [Blank New Tab Dark Mode](https://chrome.google.com/webstore/detail/blank-new-tab-dark-mode/kbgpnmhanjagjnkiekpnkcefiafpapfa/)
- [Dark Reader](https://chrome.google.com/webstore/detail/dark-reader/eimadpbcbfnmbkopoojfekhnkhdbieeh)
- [Chrome Dev Tools New Moon Theme](https://github.com/taniarascia/new-moon-chrome-devtools)
- [Extensify](https://chrome.google.com/webstore/detail/extensity/jjmflmamggggndanpgfnpelongoepncg)
- [Favioli](https://chrome.google.com/webstore/detail/favioli/pnoookpoipfmadlpkijnboajfklplgbe?hl=en)
- [I Don't Care About Cookies](https://chrome.google.com/webstore/detail/i-dont-care-about-cookies/fihnjjcciajhdojfnbdddfaoknhalnja?hl=en)
- [Minimal Twitter](https://chrome.google.com/webstore/detail/minimal-twitter/pobhoodpcipjmedfenaigbeloiidbflp?hl=en)
- [Remove W3Schools](https://chrome.google.com/webstore/detail/remove-w3schools/gohnadkcefpdhblajddfnhapimpdjkje?hl=en-US)
- [Simplify Gmail](https://chrome.google.com/webstore/detail/simplify-gmail/pbmlfaiicoikhdbjagjbglnbfcbcojpj?hl=en)

## MacOS Links

- [Open in Code](https://github.com/sozercan/OpenInCode) - macOS Finder toolbar app to open current folder in Visual Studio Code
- [Setting Up a New MacBook for JavaScript Development](https://medium.com/javascript-scene/setting-up-a-new-macbook-for-javascript-development-289df3f8f9)
- [Setting up a Brand New Mac for Development](https://www.taniarascia.com/setting-up-a-brand-new-mac-for-development/)
- [Manage Password with GPG, Git and PasswordStore](https://www.fluidkeys.com/docs/use-pass-with-fluidkeys/)

## FAQ

### Override default settings

### Useful Links

- <https://misc.flogisoft.com/bash/tip_colors_and_formatting>
- <https://www.booleanworld.com/customizing-coloring-bash-prompt>
- <https://github.com/herrbischoff/awesome-macos-command-line>
- <https://github.com/dylanaraps/pure-bash-bible>
- <https://arslan.io/2019/07/03/how-to-write-idempotent-bash-scripts/>
- <https://medium.com/@vdeantoni/setting-up-your-mac-for-web-development-in-2020-659f5588b883>
- <https://medium.com/swlh/my-favorite-cli-tools-c2fa484cee52>
- <https://darrenburns.net/posts/tools/>
- <https://medium.com/better-programming/boost-your-command-line-productivity-with-fuzzy-finder-985aa162ba5d>
- <https://github.com/jorgebucaran/cookbook.fish>

