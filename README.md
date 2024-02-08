# fbctl - Unofficial Pure Storage FlashBlade command line utility

fbctl is an unofficial command-line utility to interact with Pure Storage FlashBlade. At this point fbctl supports configuring bi-directional object replication between two FlashBlades. 

## Prerequisites 
- API Client setup on FlashBalde must be completed and private key in PEM format should be saved before using this tool
- Release package containes an appsettings.json file, this file should be filled with the details of the API client setup on FlashBlade.
- Network access to FlashBlade management IP

## Usage
```
./fbctl
USAGE:
    fbctl [OPTIONS] <COMMAND>

OPTIONS:
    -h, --help       Prints help information
    -v, --version    Prints version information

COMMANDS:
    bidirrep
```
```
./fbctl bidirrep
USAGE:
    fbctl bidirrep [OPTIONS] <COMMAND>

OPTIONS:
    -h, --help    Prints help information

COMMANDS:
    validate <array1> <array2>  - Ensures FlashBlade management API is accessible and configuration is correct
    create <array1> <array2> - Creates a new bucket and configures bi-directional replication
```
```
./fbctl bidirrep create -h
USAGE:
    fbctl bidirrep create <array1> <array2> [OPTIONS]

ARGUMENTS:
    <array1>    Name of the first FlashBlade. Must match the name in the appsettings.json
    <array2>    Name of the second FlashBlade. Must match the name in the appsettings.json

OPTIONS:
                                     DEFAULT
    -h, --help                                  Prints help information
        --account                               Name of the account to be used
        --create-account                        Flag for new account creation
        --new-user                              Name of the new user to be created
        --new-user-policies                     Command seperated list of policies for the new user
        --replication-user                      Name of the replication user to be used
        --create-replication-user               Flag for new replication user creation
        --bucket                                Name of the bucket to be created
        --public-bucket                         Flag for setting public access for the bucket
        --retention                  7          Retention duration in days for object versioning
```
## Example
```
./fbctl bidirrep create flashblade01 flashblade02 --account testaccount --create-account --new-user testuser1 --new-user-policies pure:policy/bucket-create,pure:policy/bucket-delete --replication-user repluser1 --create-replication-user --bucket bucket1 --public-bucket --retention 5
```
