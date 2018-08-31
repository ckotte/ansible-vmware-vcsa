Ansible modules to configure VMware vCenter Server Appliance (vCSA) via REST API.

Note: Tested with vCSA 6.5 and 6.7.

# Setup

1. Create a library directory in your repository and add the repository as a submodule

~~~~
mkdir ./library
git submodule add https://github.com/ckotte/ansible-vmware-vcsa.git library/ansible-vmware-vcsa
~~~~

2. Create a module_utils directory in your repository and link the module utils

~~~~
mkdir -p ./module_utils/ansible-vmware-vcsa
cd ./module_utils/ansible-vmware-vcsa
ln -sf ../../library/ansible-vmware-vcsa/vmware_vcsa.py vmware_vcsa.py
~~~~

3. Add library and module_utils to ansible.cfg

~~~~
library = ./library
module_utils = ./module_utils/ansible-vmware-vcsa
~~~~
