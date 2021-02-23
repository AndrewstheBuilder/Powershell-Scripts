# robocopy 'SRC' 'DEST' /e /z /SEC /R:0 /W:0 /xf *
# To check if directory is hidden run: "dir /A:S" in directory that contains hidden directory
# In cmd run " attrib -h  -s  -a "C:\My hidden folder" " if robocopy hides DEST

robocopy '\\unfcsd.unf.edu\files\global\PhysFac' 'C:\Users\AndrewsP\Documents\Add-FullControl\Test(RoboCopy)' /e /z /SEC /R:0 /W:0 /xf *
robocopy 'C:\Users\AndrewsP\Documents\Add-FullControl\Nice Folder' 'C:\Users\AndrewsP\Documents\Add-FullControl\Test(RoboCopy)' /purge