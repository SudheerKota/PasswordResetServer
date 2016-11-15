# PasswordResetSystem
Contains all the code pertinent to the password reset system.
All source code for each component of the system will be kept under it's own branch.
The master branch contains the structure of how each component will be laid out in the directory hierarchy so, that there are no merge conflicts between sub-components.
Top level directories can be assumed to have their own "master" branch.

# Building The Project
This section describes how to build/assemble/distribute the GRVTY Password Reset System.
## Project Building Overview
An executable file "GrvtyApp" has been provided at the root of the project repository, to facilitate rapid prototyping and iteration, of the various builds.
The builds can be summarized as:
- Local Development: Development on a personal machine.
- Development Server: Integration testing on a shared server.
- Production Server: Production ready release.
- Client Development Release: Client integration testing
- Client Production Release: Client production ready release.

## Project Build Requirements
The automated build process requires Python 3 and is facilitated by the "GrvtyApp" executable file, please refer to it for further documentation.
```bash
./GrvtyApp --help
```

# Implementation notes
This section describes important implementation notes that each component of the system will need to implement to facilitate a 1-click system build (internal/external), 1-click demo app deployment (internal).
- Each component is responsible for it's own .gitignore file
- Each component is responsible for it's own build process (internal/external)
- The root directory will call each sub-components build tool and create the directory hierarchy which will contain all the built components.
- Each component should do a complete build including documentation.
- Each component build tool is required to accept the following parameters
  - distType ("internal" or "external") - to either build for internal or external usage
  - output - the directory to output the results (e.g. compiled code). The supplied directory can be assumed to be empty, so that there are no namespace collisions. Unless otherwise explicitly specified.

Note: Once documentation has been made public, the published documentation/code represents a stable code base. This means only documentation/code that is known

# Structure
This section describes the current directory hierarchy of the components for the Password Reset System.

## Documentation
The Documentation directory contains general system documentation including, but not limited to system architecture, release notes, internal documentation, internal build procedures, etc.
This directory should not contain any component specific documentation (e.g. api references).

## GrvtySDK
The GrvtySDK directory contains all source code for the Software Development Kits (SDKs) needed to run the server and client components of the password reset system.

## IntegrationExamples
The IntegrationExamples directory contains code for the public code that will be released to provide examples on how to integrate the server and client password reset system SDKs.
