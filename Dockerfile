FROM node:slim

# 强制指定 npm 安装路径
RUN npm config set registry https://registry.npmmirror.com \
    && npm i -g wrangler

RUN apt-get -qq update \
    && apt-get -qq install zsh curl git procps net-tools -y \
    && apt-get -qq autoclean \
    && rm -rf /var/lib/apt/lists/*

# 安装 zsh 和插件
RUN zsh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" \
    && git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting \
    && git clone https://github.com/zsh-users/zsh-autosuggestions.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions \
    && sed -i "s/plugins=(git)/plugins=(git zsh-syntax-highlighting zsh-autosuggestions docker kubectl brew golang history nmap node npm pip pipenv pyenv pylint python screen sublime)/g" ~/.zshrc

EXPOSE 8787 5173
CMD []
ENTRYPOINT ["/usr/bin/zsh"]

# docker build -t node:cem --progress=plain .
