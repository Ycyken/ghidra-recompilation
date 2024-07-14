from src.PostProcessor import PostProcessor
import sys

if __name__ == "__main__":
    if len(sys.argv) == 2:
        postProcessor = PostProcessor(sys.argv[1])
        postProcessor.run()
    else:
        print("File name required")
