# Eric Zimmerman Tool Automation

There are two scripts in this folder; first off is the Get-EricZimmermanToolAnalysis.ps1 script. This script is meant to run eight different Eric Zimmerman tools against a forensic image.

Second is the Get-UniqueEventIDs.ps1. This is an optional second-stage script that will parse the event log output that EvtxECmd generates and extract all 'interesting' events.
These events are based off of all the identified Event IDs on the SANS Hunt Evil poster, as well as a few from personal experience.
It can be expanded on should you like to customize it.