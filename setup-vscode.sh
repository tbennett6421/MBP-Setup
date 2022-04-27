#!/usr/bin/env zsh

source ./utils.sh

if ! [ -d $HOME/Library/Application\ Support/Code/User ]; then
  errorMessage "Missing Visual Studio Code settings folder $HOME/Library/Application Support/Code/User"
  exit 1
fi

# Create the settings file if Missing
touch $HOME/Library/Application\ Support/Code/User/settings.json
# Backup Visual Studio Code Settings
cp $HOME/Library/Application\ Support/Code/User/settings.json{,.bak}

PLUGINS=(
  # Rubymaniac.vscode-paste-and-indent
  # alefragnani.Bookmarks
  # alexcvzz.vscode-sqlite
  # alexdima.copy-relative-path
  # andrejunges.Handlebars
  # andrewmarkle.primer-light
  # andys8.jest-snippets
  # bibhasdn.unique-lines
  # bierner.markdown-preview-github-styles
  # bungcip.better-toml
  # christian-kohler.npm-intellisense
  # christian-kohler.path-intellisense
  # codezombiech.gitignore
  # CoenraadS.bracket-pair-colorizer-2
  # dakara.transformer
  # darkriszty.markdown-table-prettify
  # dbaeumer.vscode-eslint
  # drKnoxy.eslint-disable-snippets
  # eamodio.gitlens
  # EditorConfig.EditorConfig
  # emmanuelbeziat.vscode-great-icons
  # esbenp.prettier-vscode
  # fabiospampinato.vscode-open-in-finder
  # fabiospampinato.vscode-open-in-gittower
  # felipecaputo.git-project-manager
  # formulahendry.auto-rename-tag
  # geeksharp.openssl-configuration-file
  # ghmcadams.lintlens
  # Gruntfuggly.todo-tree
  # humao.rest-client
  # mikestead.dotenv
  # mrmlnc.vscode-duplicate
  # ms-azuretools.vscode-docker
  # nwallace.peep
  # Orta.vscode-jest
  # patbenatar.advanced-new-file
  # shd101wyy.markdown-preview-enhanced
  # sleistner.vscode-fileutils
  # streetsidesoftware.code-spell-checker
  # tombonnike.vscode-status-bar-format-toggle
  # wmaurer.vscode-jumpy
  )

for s in "${PLUGINS[@]}"; do
  code --install-extension "$s" --force
done

# Restore backup of Visual Studio Code Settings
mv $HOME/Library/Application\ Support/Code/User/settings.json.bak $HOME/Library/Application\ Support/Code/User/settings.json
