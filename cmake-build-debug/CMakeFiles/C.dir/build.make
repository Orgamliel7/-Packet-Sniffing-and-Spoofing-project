# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = "/mnt/c/אור/networkProject BL/C"

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = "/mnt/c/אור/networkProject BL/C/cmake-build-debug"

# Include any dependencies generated for this target.
include CMakeFiles/C.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/C.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/C.dir/flags.make

CMakeFiles/C.dir/sniffer.c.o: CMakeFiles/C.dir/flags.make
CMakeFiles/C.dir/sniffer.c.o: ../sniffer.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/mnt/c/אור/networkProject BL/C/cmake-build-debug/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/C.dir/sniffer.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/C.dir/sniffer.c.o   -c "/mnt/c/אור/networkProject BL/C/sniffer.c"

CMakeFiles/C.dir/sniffer.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/C.dir/sniffer.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E "/mnt/c/אור/networkProject BL/C/sniffer.c" > CMakeFiles/C.dir/sniffer.c.i

CMakeFiles/C.dir/sniffer.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/C.dir/sniffer.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S "/mnt/c/אור/networkProject BL/C/sniffer.c" -o CMakeFiles/C.dir/sniffer.c.s

CMakeFiles/C.dir/sniffSpoof.c.o: CMakeFiles/C.dir/flags.make
CMakeFiles/C.dir/sniffSpoof.c.o: ../sniffSpoof.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/mnt/c/אור/networkProject BL/C/cmake-build-debug/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/C.dir/sniffSpoof.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/C.dir/sniffSpoof.c.o   -c "/mnt/c/אור/networkProject BL/C/sniffSpoof.c"

CMakeFiles/C.dir/sniffSpoof.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/C.dir/sniffSpoof.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E "/mnt/c/אור/networkProject BL/C/sniffSpoof.c" > CMakeFiles/C.dir/sniffSpoof.c.i

CMakeFiles/C.dir/sniffSpoof.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/C.dir/sniffSpoof.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S "/mnt/c/אור/networkProject BL/C/sniffSpoof.c" -o CMakeFiles/C.dir/sniffSpoof.c.s

CMakeFiles/C.dir/spoof.c.o: CMakeFiles/C.dir/flags.make
CMakeFiles/C.dir/spoof.c.o: ../spoof.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/mnt/c/אור/networkProject BL/C/cmake-build-debug/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/C.dir/spoof.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/C.dir/spoof.c.o   -c "/mnt/c/אור/networkProject BL/C/spoof.c"

CMakeFiles/C.dir/spoof.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/C.dir/spoof.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E "/mnt/c/אור/networkProject BL/C/spoof.c" > CMakeFiles/C.dir/spoof.c.i

CMakeFiles/C.dir/spoof.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/C.dir/spoof.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S "/mnt/c/אור/networkProject BL/C/spoof.c" -o CMakeFiles/C.dir/spoof.c.s

# Object files for target C
C_OBJECTS = \
"CMakeFiles/C.dir/sniffer.c.o" \
"CMakeFiles/C.dir/sniffSpoof.c.o" \
"CMakeFiles/C.dir/spoof.c.o"

# External object files for target C
C_EXTERNAL_OBJECTS =

C : CMakeFiles/C.dir/sniffer.c.o
C : CMakeFiles/C.dir/sniffSpoof.c.o
C : CMakeFiles/C.dir/spoof.c.o
C : CMakeFiles/C.dir/build.make
C : CMakeFiles/C.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir="/mnt/c/אור/networkProject BL/C/cmake-build-debug/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_4) "Linking C executable C"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/C.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/C.dir/build: C

.PHONY : CMakeFiles/C.dir/build

CMakeFiles/C.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/C.dir/cmake_clean.cmake
.PHONY : CMakeFiles/C.dir/clean

CMakeFiles/C.dir/depend:
	cd "/mnt/c/אור/networkProject BL/C/cmake-build-debug" && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" "/mnt/c/אור/networkProject BL/C" "/mnt/c/אור/networkProject BL/C" "/mnt/c/אור/networkProject BL/C/cmake-build-debug" "/mnt/c/אור/networkProject BL/C/cmake-build-debug" "/mnt/c/אור/networkProject BL/C/cmake-build-debug/CMakeFiles/C.dir/DependInfo.cmake" --color=$(COLOR)
.PHONY : CMakeFiles/C.dir/depend
