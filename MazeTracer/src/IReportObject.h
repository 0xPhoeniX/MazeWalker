#pragma once
#include "json/json.h"


namespace MazeWalker {

    // Interface class for serializing object into json object
	class IReportObject {
	public:
		virtual bool toJson( Json::Value &root ) const = 0;
	};
}