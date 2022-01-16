#pragma once


namespace MazeWalker {
	class Logger {
	public:
		static void Write(const char* format, ...);
	};
}