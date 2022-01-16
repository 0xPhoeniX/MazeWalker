#pragma once


namespace MazeWalker {

    // Interface class for serializing object into json object
    class IReportObject {
    public:
        virtual bool toJson(void *root ) const = 0;
    };
}