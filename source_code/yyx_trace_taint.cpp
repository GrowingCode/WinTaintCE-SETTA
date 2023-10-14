#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <iostream>
#include <fstream>
#include <windows.h>

#include "yyx_trace.h"
#include "yyx_engine.h"
#include "yyx_trace_taint.h"
#include "symbolic_execution.h"
#include "taint_fuzzing.h"
#include "yyx_global_info.h"

YEssenTaintedTrace* GetEssenTaintedTraceFromFile(std::string tpath) {
	YTrace* yte = new YTrace(false, tpath);
	YTaint* yt = new YTaint(yte);
	yt->HandleTaintInTrace();
	YTaintedTrace* ytt = new YTaintedTrace(yt);
	YEssenTaintedTrace* yett = new YEssenTaintedTrace(ytt);
	delete yte;
	delete yt;
	delete ytt;
	return yett;
}



