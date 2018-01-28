#pragma once
#include "MemoryArea.h"
#include "IReportObject.h"
#include "Image.h"


namespace MazeWalker {

	// Singleton class to manage tracing process.
	class ProcessTrace : IReportObject {
	public:
		~ProcessTrace() {}

		// Should this address be traced. It goes according to the 
		// configuration white-listing.
		bool isAddressInScope(int address) const;

		void addImage(Image* img);
		void addMemoryArea(MemoryArea* ma);

		// Export the whole tracing accumulated info into the json
		// file.
		//
		// dir: The directory to store the results.
		void Export(const char* dir) const;
		bool toJson(Json::Value& root) const;

		static ProcessTrace& Instance();

		// Initialize the tracing process based on the configuration
		// file. If the configuration parsing succeeded, we are good to go.
		static bool Initialize(const char* config_file);

	private:
		ProcessTrace();
		ProcessTrace(const ProcessTrace& other);
		ProcessTrace& operator=(const ProcessTrace& other);

		void* _mas;
		void* modules;
	};
}