#pragma once
#include "PythonAnalysis.h"
#include "Call.h"


namespace MazeWalker {

	// Class for conducting call site analysis with python scripts.
	class CallAnalysis : public PythonBasedAnalysis {
	public:
		CallAnalysis();
		virtual ~CallAnalysis();
		virtual bool toJson( Json::Value& root ) const;
	protected:
		CallAnalysis(const CallAnalysis& other) {}
		CallAnalysis& operator=(const CallAnalysis& other) {}

		// Internal function which actually calls the python analysis script.
		//
		// mod:       python module
		// fname:     function name in the module file
		// param_num: the number of parameters the analyzed API has
		// params:    stack address where the first parameter starts
		void call_analyzer(const char* mod, const char* fname, short param_num, long* params);
		char* json_result;
	};

	// The class analyzes call size before invocation
	class PreCallAnalysis : public CallAnalysis {
	public:
		PreCallAnalysis(int EBP, const Call& call);
	};

	// The class analyzes call size after invocation and before return
	class PostCallAnalysis : public CallAnalysis {
	public:
		PostCallAnalysis(int EBP, const Call& call);
	};
}