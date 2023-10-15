Note that you should replace 'C:/HomeSpace/CTaintAnalysis/yyx_trace_taint/run-env/' to your absolute path which puts these simplest examples.
We print the origin non-taint trace in this time to let reviewers see origin trace length. 
The taint analysis is shown offline to let reviewers see the taint details. 

The following line is the command line:

C:/HomeSpace/CTaintAnalysis/yyx_trace_taint/run-env/run-pack/yyx_trace_taint.exe -drrun_path  "C:/HomeSpace/BinaryAnalysis/DynamoRIO-Windows-10.0.0/bin64/drrun.exe" -exe_path  "C:/HomeSpace/CTaintAnalysis/yyx_trace_taint/run-env/simple-example/libfile-simple.exe" -yyx_taint_dll_path "C:/HomeSpace/CTaintAnalysis/yyx_trace_taint/run-env/yt-pack/yyx_taint.dll" -folder_put_instr_val_trace  "C:/HomeSpace/BinarySymbolicOutput" -folder_put_generated_seeds "C:/HomeSpace/BinaryFuzzInput" -folder_put_temp_generated_seeds "C:/HomeSpace/BinaryFuzzTempInput"



