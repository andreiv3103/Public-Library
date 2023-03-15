# Install or Upgrade the AIP Client
* This is the main script that needs to be used in the PowerShell App Deploy Toolkit solution to create an AIP Client upgrade package.
* The solution is going to uninstall any existing AIP client installations and install the version from the package.
## How to use
* Download Powershell App Deploy Toolkit (from [here](https://github.com/andreiv3103/Misc/blob/2ff649a481a61d4b03d945e94514a68b7983ab82/App%20Management%20Scripts/Other/Uninstall%20AIP%20Client/Uninstall%20AIP%20Client.ps1))
* Unpack the download.
* Go to the folder where the archive was unpacked and then in the 'Toolkit' subfolder.
* Replace the `Deploy-Application.ps1` file from there with the one in this repo. That is the main script file.
* Replace `AppDeployToolkit\AppDeployToolkitExtensions.ps1` with the file from this repo. This file contains the custom uninstall function.
* In the `Files` subfolder from the `Toolkit` folder, copy the AIP Client installer MSI (It can be downloaded from [here](https://www.microsoft.com/en-us/download/details.aspx?id=53018)). Please make sure you downloaded the MSI version and NOT the EXE version.
* Now use the contents of the `Toolkit` folder to create an SCCM application package.
* For a detailed training on how to use PSADT with SCCM, please go through this series of YouTube videos: https://www.youtube.com/watch?v=J6V67Mpolqc