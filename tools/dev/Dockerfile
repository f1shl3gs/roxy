FROM alpine:3.16.2

ARG SSH_PUB_KEY

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.tuna.tsinghua.edu.cn/g' /etc/apk/repositories

RUN apk add --no-cache curl wget ca-certificates tzdata vim openssh-server \
    && mkdir -p /root/.ssh \
    && chmod 0700 /root/.ssh \
    && echo "$SSH_PUB_KEY" > /root/.ssh/authorized_keys \
    && ssh-keygen -A \
    && echo -e "PasswordAuthentication no" >> /etc/ssh/sshd_config

ENTRYPOINT ["/usr/sbin/sshd", "-D"]