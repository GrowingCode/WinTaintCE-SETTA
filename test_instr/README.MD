## Tool Usage

At first, the CommonRunTutorialAndCompiledTool contains the compiled version of the tool. 

Follow the instruction in that directory to run tool for the simplest case. 

If the simplest case is successfully start up, replace the to-be-test exe with the exe in Test-Prefix directory. 

Note that, we discover that the pandel of WinAFL often shows that it find 5 paths by running a single seed for 5-10 rounds without any mutation, so to make the comparison fair, after generating seeds by WinTaintCE, we also let WinAFL take the generated seeds by WinTaintCE as the initial seeds and run for 15 minutes. The running time of WinTaintCE subtracts 15 minutes accordingly. 

We also provide tutorial about how to run WinAFL. 

In summary, we use WinAFL's statistical results to evaluate the number of discovered paths. 



