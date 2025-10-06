import os
import magic
import multiprocessing

class FileSystem:
    def __init__(self, root_path):
        self.root_path = root_path

    def traverse_filesystem(self):
        """
        Traverse the filesystem starting from the root_path.
        """
        for dirpath, dirnames, filenames in os.walk(self.root_path):
            yield dirpath, dirnames, filenames

    def get_all_binaries(self):
        """
        Get all binary files in the filesystem using the 'file' command.
        """
        binaries = []
        for dirpath, _, filenames in self.traverse_filesystem():
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                file_type = self.get_file_type_with_timeout(filepath)
  
                if 'executable' in file_type:
                    binaries.append(filepath)
        return binaries

    def get_all_libraries(self):
        """
        Get all library files in the filesystem using the 'file' command.
        """
        libraries = []
        for dirpath, _, filenames in self.traverse_filesystem():
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                file_type = self.get_file_type_with_timeout(filepath)
                if 'shared object' in file_type:
                    libraries.append(filepath)
        return libraries

    def get_file_type(self, filepath):
        try:
            output = magic.from_file(filepath)
            return output.lower()
        except:
            return "unknown"

    def get_file_type_with_timeout(self, filepath):
        result_queue = multiprocessing.Queue()
        process = multiprocessing.Process(
            target=self.get_file_type_worker, args=(filepath, result_queue)
        )
        process.start()
        process.join(timeout=5)  # Set the timeout value to 5 seconds

        if process.is_alive():
            process.terminate()
            process.join()
            # print(f"Timeout occurred for {filepath}")
            return ""
        else:
            result = result_queue.get()
            if isinstance(result, Exception):
                # print(f"Error occurred for {filepath}: {result}")
                return ""
            return result

    def get_file_type_worker(self, filepath, result_queue):
        try:
            output = magic.from_file(filepath)
            result_queue.put(output.lower())
        except Exception as e:
            result_queue.put(e)

