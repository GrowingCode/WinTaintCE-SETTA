## Tool Usage

At first, the CommonRunTutorialAndCompiledTool contains the compiled version of the tool. 

Follow the instruction in that directory to run tool for the simplest case. 

If the simplest case is successfully start up, replace the to-be-test exe with the exe in Test-Prefix directory. 

Note that, we discover that the pandel of WinAFL often shows that it find 5 paths by running a single seed for 5-10 rounds without any mutation, so to make the comparison fair, after generating seeds by WinTaintCE, we also let WinAFL take the generated seeds by WinTaintCE as the initial seeds and run for 15 minutes. The running time of WinTaintCE subtracts 15 minutes accordingly. 

We also provide tutorial about how to run WinAFL. 

In summary, we use WinAFL's statistical results to evaluate the number of discovered paths. 


# Use of WinTaintCE

1.	Download the executable file of the Winlib library on our open-source WinTaintCE GitHub.

2.	Randomly select 5-10 seed files from the initial_seeds we provide as input to WinTaintCE, obtain instr_traces, and obtain total_paths results.

    The following line is the command line:

    C:/HomeSpace/CTaintAnalysis/yyx_trace_taint/run-env/run-pack/yyx_trace_taint.exe -drrun_path "C:/HomeSpace/BinaryAnalysis/DynamoRIO-Windows-10.0.0/bin64/drrun.exe" -exe_path  "C:/HomeSpace/CTaintAnalysis/yyx_trace_taint/run-env/simple-example/libfile-simple.exe" -yyx_taint_dll_path "C:/HomeSpace/CTaintAnalysis/yyx_trace_taint/run-env/yt-pack/yyx_taint.dll" -folder_put_instr_val_trace  "C:/HomeSpace/BinarySymbolicOutput" -folder_put_generated_seeds "C:/HomeSpace/BinaryFuzzInput" -folder_put_temp_generated_seeds "C:/HomeSpace/BinaryFuzzTempInput"

    Note that you should replace 'C:/HomeSpace/CTaintAnalysis/yyx_trace_taint/run-env/' to your absolute path which puts these simplest examples.
    We print the origin non-taint trace in this time to let reviewers see origin trace length. 
    The taint analysis is shown offline to let reviewers see the taint details.


# Use of WinAFL

1.	Download DynamoRio（https://dynamorio.org/page_releases.html）
2.  Download WinAFL（https://github.com/googleprojectzero/winafl）
3.  Enter the command prompt tool (cmd) in the directory of WinAFL and use the following command:
    mkdir build64
    cd build64
    cmake -A x64 .. -DDynamoRIO_DIR=..\path\to\DynamoRIO\cmake
    cmake --build . --config Release
4.  Create new folders “in” and “out” in the ..\winafl\build64\bin\Release
5.  Place the seed file 5bytes.bin in the folder ”in”
6.  Place the executable file libfile-simple.exe in the folder “Release”
7.  afl-fuzz testing use the following command：
    afl-fuzz.exe -i in -o out -D DynamoRIO_path\bin64 -t 20000 -- -coverage_module test_sodium.exe -fuzz_iterations 5000 -target_module test_sodium.exe -target_method main -nargs 2 -- test_sodium.exe @@

NOTE:
    afl-fuzz [afl options] -- [instrumentation options] -- target_cmd_line

    [afl options] Insertion parameters
    -i dir		——Directory for samples
    -o dir		——Save output data
    -D dir		——Path to DynamoRIO
    -t msec		——The timeout time for each sample execution
    
    [instrumentation options] Target program parameters
    -coverage_module 	——Module for calculating coverage 
    -fuzz_iterations		——Maximum number of iterations
    -target_module		——Target program, containing the objective function to be fuzzified
    -target_method		——Objective function name
    -nargs          		——The number of parameters required for the execution of the target program (including the target program itself)
    
    @@					——Reference test cases in the - i parameter






