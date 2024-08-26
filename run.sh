#!/bin/bash
# run customized ansible image and mount necessary directories

ansible_image_version=($(tar -cf - .ansible-runner | md5sum))


# run prepared tasks
prep() {

    case "$1" in
    "task")
        echo "bbb"
        exit
        ;;
    esac
    echo "taks not found run args as command"
}


main() {


ansible_cmd="$@"

prep $ansible_cmd

if [ -z "$(docker images -q homelab-ansible:$ansible_image_version 2> /dev/null)" ]; then
  echo "docker not exist"
  docker build -t=homelab-ansible:$ansible_image_version .ansible-runner
fi

if [ "$1" == "ansible-playbook" ] && grep -qve "-i " <(echo "$@"); then
    ansible_cmd+=" -i inventories/hosts.ini"
fi

docker run -it --rm \
    -v /home/$USER/.ssh/:/root/.ssh \
    -v /home/$USER/.kube/:/root/.kube:ro \
    -v $PWD:/repo/ \
    homelab-ansible:$ansible_image_version \
    "chown -R 600:600 /root/.ssh;chown -R root:root /root/.ssh; $ansible_cmd"

}

main "$@"
