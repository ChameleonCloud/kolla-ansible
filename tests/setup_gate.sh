#!/bin/bash

set -o xtrace
set -o errexit
set -o pipefail

# Enable unbuffered output for Ansible in Jenkins.
export PYTHONUNBUFFERED=1


function setup_openstack_clients {
    # Prepare virtualenv for openstack deployment tests
    local packages=(python-openstackclient python-heatclient)
    if [[ $SCENARIO == zun ]]; then
        packages+=(python-zunclient)
    fi
    if [[ $SCENARIO == ironic ]]; then
        packages+=(python-ironicclient python-ironic-inspector-client)
    fi
    if [[ $SCENARIO == magnum ]]; then
        packages+=(python-designateclient python-magnumclient python-troveclient)
    fi
    if [[ $SCENARIO == octavia ]]; then
        packages+=(python-octaviaclient)
    fi
    if [[ $SCENARIO == masakari ]]; then
        packages+=(python-masakariclient)
    fi
    if [[ $SCENARIO == scenario_nfv ]]; then
        packages+=(python-tackerclient python-barbicanclient python-mistralclient)
    fi
    if [[ $SCENARIO == ovn ]]; then
        packages+=(python-octaviaclient)
    fi
    if [[ "debian" == $BASE_DISTRO ]]; then
        sudo apt -y install python3-venv
    fi
    python3 -m venv ~/openstackclient-venv
    ~/openstackclient-venv/bin/pip install -U pip
    ~/openstackclient-venv/bin/pip install -c $UPPER_CONSTRAINTS ${packages[@]}
}

function prepare_images {
    if [[ "${BUILD_IMAGE}" == "False" ]]; then
        return
    fi

    if [[ $SCENARIO != "bifrost" ]]; then
        GATE_IMAGES="^cron,^fluentd,^glance,^haproxy,^keepalived,^keystone,^kolla-toolbox,^mariadb,^memcached,^neutron,^nova-,^openvswitch,^rabbitmq,^horizon,^heat,^placement"
    else
        GATE_IMAGES="bifrost"
    fi

    if [[ $SCENARIO == "cephadm" ]]; then
        GATE_IMAGES+=",^cinder"
    fi

    if [[ $SCENARIO == "cells" ]]; then
        GATE_IMAGES+=",^proxysql"
    fi

    if [[ $SCENARIO == "zun" ]]; then
        GATE_IMAGES+=",^zun,^kuryr,^etcd,^cinder,^iscsid"
        if [[ $BASE_DISTRO != "centos" && $BASE_DISTRO != "rocky" ]]; then
            GATE_IMAGES+=",^tgtd"
        fi
    fi

    if [[ $SCENARIO == "scenario_nfv" ]]; then
        GATE_IMAGES+=",^aodh,^tacker,^mistral,^redis,^barbican"
    fi
    if [[ $SCENARIO == "ironic" ]]; then
        GATE_IMAGES+=",^dnsmasq,^ironic,^iscsid"
    fi
    if [[ $SCENARIO == "magnum" ]]; then
        GATE_IMAGES+=",^designate,^magnum,^trove"
    fi
    if [[ $SCENARIO == "octavia" ]]; then
        GATE_IMAGES+=",^octavia"
    fi
    if [[ $SCENARIO == "masakari" ]]; then
        GATE_IMAGES+=",^masakari-,^hacluster-"
    fi

    if [[ $SCENARIO == "swift" ]]; then
        GATE_IMAGES+=",^swift"
    fi

    if [[ $SCENARIO == "ovn" ]]; then
        GATE_IMAGES+=",^octavia,^ovn"
    fi

    if [[ $SCENARIO == "mariadb" ]]; then
        GATE_IMAGES="^cron,^fluentd,^haproxy,^keepalived,^kolla-toolbox,^mariadb"
    fi

    if [[ $SCENARIO == "lets-encrypt" ]]; then
        GATE_IMAGES+=",^letsencrypt,^haproxy"
    fi

    if [[ $SCENARIO == "prometheus-opensearch" ]]; then
        GATE_IMAGES="^cron,^fluentd,^grafana,^haproxy,^keepalived,^kolla-toolbox,^mariadb,^memcached,^opensearch,^prometheus,^rabbitmq"
    fi

    if [[ $SCENARIO == "venus" ]]; then
        GATE_IMAGES="^cron,^elasticsearch,^fluentd,^haproxy,^keepalived,^keystone,^kolla-toolbox,^mariadb,^memcached,^rabbitmq,^venus"
    fi

    sudo tee -a /etc/kolla/kolla-build.conf <<EOF
[profiles]
gate = ${GATE_IMAGES}
EOF

    mkdir -p /tmp/logs/build

    sudo $CONTAINER_ENGINE run -d --net=host -e REGISTRY_HTTP_ADDR=0.0.0.0:4000 --restart=always -v /opt/kolla_registry/:/var/lib/registry --name registry quay.io/libpod/registry:2.8.2

    python3 -m venv ~/kolla-venv
    . ~/kolla-venv/bin/activate

    pip install "${KOLLA_SRC_DIR}" "requests<2.32"

    sudo ~/kolla-venv/bin/kolla-build

    # NOTE(yoctozepto): due to debian buster we push after images are built
    # see https://github.com/docker/for-linux/issues/711
    if [[ "debian" == $BASE_DISTRO ]]; then
        for img in $(sudo ${CONTAINER_ENGINE} image ls --format '{{ .Repository }}:{{ .Tag }}' | grep lokolla/); do
            sudo $CONTAINER_ENGINE push $img;
        done
    fi

    deactivate
}


setup_openstack_clients

RAW_INVENTORY=/etc/kolla/inventory

source $KOLLA_ANSIBLE_VENV_PATH/bin/activate
kolla-ansible -i ${RAW_INVENTORY} -vvv bootstrap-servers &> /tmp/logs/ansible/bootstrap-servers
deactivate

prepare_images
