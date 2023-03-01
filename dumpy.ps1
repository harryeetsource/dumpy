# Define the path where your .dmp files are located
$dmpPath = "."

# Get all .dmp files in the specified directory
$dmpFiles = Get-ChildItem -Path $dmpPath -Filter *.dmp

# Loop through each .dmp file and create a directory with its name
foreach ($file in $dmpFiles) {
    $directoryName = $file.BaseName
    New-Item -ItemType Directory -Path "$dmpPath\$directoryName"

    # Run dumpy.exe with the path of the dmp file and output to the newly created directory
    $outputPath = "$dmpPath\$directoryName\$directoryName.exe"
    & ".\dumpy.exe" $file.FullName  $outputPath
}
