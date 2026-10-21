@echo off
echo [autoexec] Mixed-case echo text must remain mixed-case.

ver
vol

echo [autoexec] Creating real nested directories.
mkdir NestedParent\NestedChild
cd NestedParent
dir
cd NestedChild
dir
cd ..\..

echo [autoexec] Creating real directory NT61_Test.
mkdir NT61_Test
cd NT61_Test
dir
cd ..

echo [autoexec] Removing real directory NT61_Test.
rmdir NT61_Test
dir

echo [autoexec] Complete.
