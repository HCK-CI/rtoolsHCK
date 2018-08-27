
# rtoolsHCK

rtoolsHCK is a ruby gem tool-kit based on [toolsHCK](https://github.com/HCK-CI/toolsHCK) for managing and maintaining the HCK setup remotely.

## Getting Started

Follow these instructions to install and start using rtoolsHCK.

### Prerequisites

What things you need to install the gem

* [net-telnet](https://github.com/ruby/net-telnet)
* [winrm](https://github.com/WinRb/WinRM)
* [winrm-fs](https://github.com/WinRb/winrm-fs)

### Installing

Execute this command in the git clone's directory
```
rake build
rake install
```
## Usage

Creating a rtoolsHCK session to create a new "test" pool and list the pools info
```
require 'rtoolsHCK'

rtoolsHCK_session = RToolsHCK::new('10.0.0.10', 'Administrator', 'password', '.')

rtoolsHCK_session.create_pool('test')
rtoolsHCK_session.list_pools
rtoolsHCK_session.close
```

Creating a rtoolsHCK session to shutdown the two clients and the controller's machines
```
require 'rtoolsHCK'

rtoolsHCK_session = RToolsHCK::new('10.0.0.10', 'Administrator', 'password', '.')

rtoolsHCK_session.machine_shutdown('cl1-win10x64')
rtoolsHCK_session.machine_shutdown('cl2-win10x64')
rtoolsHCK_session.close_and_shutdown
```

## All action methods

* list_pools_info
* create_pool
* delete_pool
* move_machine
* set_machine_state
* delete_machine
* list_machine_targets
* list_projects
* create_project
* delete_project
* create_project_target
* delete_project_target
* list_tests
* get_test_info
* queue_test
* get_test_results
* create_project_package
* get_machine_ip
* shutdown
* machine_shutdown
* install_machine_driver_package
* reconnect
* connection_check
* close_and_shutdown
* close
* closed?

For more info execute this command in the git clone's directory
```
rake rdoc
```
And open doc/index.html with a browser.

## Authors

* **Bishara AbuHattoum**
* **Lior Haim**



