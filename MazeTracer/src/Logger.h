#pragma once


namespace MazeWalker {
	class Logger {
	public:
		static Logger& Instance();
		void Write(const char* format, ...);
	private:
		Logger();
		Logger(const Logger& other);
		Logger& operator=(const Logger& other);
	};
}