# Veracode Generate SBOM in Powershell

A simple example script generate an (CYCLONEDX or SPDX) SBOM for an app in a json file.

## Setup

Clone this repository:

    git clone https://github.com/christyson/GenerateSBOMPS.git


## Usage for a single app profile or and app profile with a sandbox

.\sbom_gen <arguments>`

Arguments:
app    : (required) Name of the application within Veracode
type   : (optional) Type of SBOM to generate; valid values are 'cyclonedx' (default) or 'spdx'
linked : (optional) Include components from linked projects or not; valid values are 'true' (default) or 'false'

## Run

To run you will need to set environment variables as follows: 

```
$ENV:Veracode_API_ID=<YOUR_API_ID>
$ENV:Veracode_API_Key=<YOUR_API_KEY_SECRET>
```

and then for an spdx that is linked run:

```
.\sbom_gen <your_app_name> spdx false
```

This method will generate an SBOM in a file called "your app name"_"type".json

If the app is not found an error message will be printed.
