/*
 *	@file 	ejsFileSystem.c
 *	@brief 	FileSystem class for the EJ System Object Model
 */
/********************************** Copyright *********************************/
/*
 *	Copyright (c) Mbedthis Software LLC, 2003-2006. All Rights Reserved.
 */
/********************************** Includes **********************************/

#include	"ejs.h"

/******************************************************************************/
/*
 *	Default Constructor
 */

/******************************************************************************/
/************************************ Methods *********************************/
/******************************************************************************/
/*
 *	function void access(string path);
 *	MOB - API insufficient. Access for read or write?
 */

static int accessProc(Ejs *ejs, EjsVar *thisObj, int argc, EjsVar **argv)
{
	int		rc;

	if (argc != 1 || !ejsVarIsString(argv[0])) {
		ejsError(ejs, EJS_ARG_ERROR, "Bad usage: access(path)");
		return -1;
	}

	rc = access(argv[0]->string, 04);

	ejsSetReturnValueToBoolean(ejs, (rc == 0) ? 1 : 0);
	return 0;
}

/******************************************************************************/
/*
 *	function void mkdir(string path);
 */

static int mkdirProc(Ejs *ejs, EjsVar *thisObj, int argc, EjsVar **argv)
{
	if (argc != 1 || !ejsVarIsString(argv[0])) {
		ejsError(ejs, EJS_ARG_ERROR, "Bad usage: mkdir(path)");
		return -1;
	}

	if (mprMakeDirPath(ejs, argv[0]->string) < 0) {
		ejsError(ejs, EJS_IO_ERROR, "Cant create directory");
		return -1;
	}
	return 0;
}

/******************************************************************************/
/*
 *	function void rmdir(string path);
 */

static int rmdirProc(Ejs *ejs, EjsVar *thisObj, int argc, EjsVar **argv)
{
	int		rc;

	if (argc != 1 || !ejsVarIsString(argv[0])) {
		ejsError(ejs, EJS_ARG_ERROR, "Bad usage: mkdir(path)");
		return -1;
	}

	rc = mprDeleteDir(ejs, argv[0]->string);

	if (rc < 0) {
		ejsError(ejs, EJS_IO_ERROR, "Cant remove directory");
		return -1;
	}
	return 0;
}

/******************************************************************************/
/*
 *	function void dirList(string path, [bool enumDirs]);
 *	MOB -- need pattern to match (what about "." and ".." and ".*"
 */

static int dirListProc(Ejs *ejs, EjsVar *thisObj, int argc, EjsVar **argv)
{
	WIN32_FIND_DATA	findData;
	HANDLE			h;
	char			path[MPR_MAX_FNAME];
	EjsVar			*array, *vp;
	uchar			enumDirs;

	if (argc < 1 || !ejsVarIsString(argv[0])) {
		ejsError(ejs, EJS_ARG_ERROR, "Bad usage: dirList(path)");
		return -1;
	}
	if (argc == 2) {
		enumDirs = ejsVarToBoolean(argv[1]);
	} else {
		enumDirs = 0;
	}
	array = ejsCreateArray(ejs, 0);
	ejsMakeObjPermanent(array, 1);

	/*
	 *	First collect the files
	 */
	mprSprintf(path, sizeof(path), "%s/*.*", argv[0]->string);
	h = FindFirstFile(path, &findData);
	if (h == INVALID_HANDLE_VALUE) {
		ejsError(ejs, EJS_ARG_ERROR, "Can't enumerate dirList(path)");
		return -1;
	}

	do {
		if (findData.cFileName[0] == '.') {
			continue;
		}
		if (!enumDirs || 
				(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
			mprSprintf(path, sizeof(path), "%s/%s", argv[0]->string, 
				findData.cFileName);
			vp = ejsCreateStringVar(ejs, path);
			ejsAddArrayElt(ejs, array, vp, EJS_SHALLOW_COPY);
			ejsFreeVar(ejs, vp);
		}
	} while (FindNextFile(h, &findData) != 0);

	FindClose(h);

	ejsSetReturnValue(ejs, array);
	ejsMakeObjPermanent(array, 0);

	/*
	 *	Can free now as the return value holds the reference
 	 */
	ejsFreeVar(ejs, array);

	return 0;
}

/******************************************************************************/
/*
 *	function void getFreeSpace();
 */

static int getFreeSpaceProc(Ejs *ejs, EjsVar *thisObj, int argc, EjsVar **argv)
{
#if UNUSED
	MprApp	*app;
	uint	space;

	app = mprGetApp(ejs);
	space = IFILEMGR_GetFreeSpace(app->fileMgr, 0);
	ejsSetReturnValueToInteger(ejs, space);
#endif

	return 0;
}

/******************************************************************************/
/*
 *	function void writeFile(string path, var data);
 */

static int writeFileProc(Ejs *ejs, EjsVar *thisObj, int argc, EjsVar **argv)
{
	MprFile		*file;
	char		*data, *buf;
	int			bytes, length, rc;

	if (argc != 2 || !ejsVarIsString(argv[0])) {
		ejsError(ejs, EJS_ARG_ERROR, "Bad usage: writeFile(path, var)");
		return -1;
	}

	if (ejsVarIsString(argv[1])) {
		data = argv[1]->string;
		length = argv[1]->length;
		buf = 0;
	} else {
		buf = data = ejsVarToString(ejs, argv[1]);
		length = strlen(data);
	}

	/*
	 *	Create fails if already present
	 */
	rc = mprDelete(ejs, argv[0]->string);
	file = mprOpen(ejs, argv[0]->string, O_CREAT | O_WRONLY | O_BINARY, 0664);
	if (file == 0) {
		ejsError(ejs, EJS_IO_ERROR, "Cant create %s", argv[0]->string);
		mprFree(buf);
		return -1;
	}

	rc = 0;
	bytes = mprWrite(file, data, length);
	if (bytes != length) {
		ejsError(ejs, EJS_IO_ERROR, "Write error to %s", argv[1]->string);
		rc = -1;
	}

	mprClose(file);

	mprFree(buf);
	return rc;
}

/******************************************************************************/
/*
 *	function string readFile(string path);
 */

static int readFileProc(Ejs *ejs, EjsVar *thisObj, int argc, EjsVar **argv)
{
	MprApp	*app;
	MprFile	*file;
	MprBuf	*buf;
	char	*data;
	int		bytes, rc;

	if (argc != 1 || !ejsVarIsString(argv[0])) {
		ejsError(ejs, EJS_ARG_ERROR, "Bad usage: readFile(path)");
		return -1;
	}
	buf = mprCreateBuf(ejs, MPR_BUF_INCR, MPR_MAX_BUF);
	if (buf == 0) {
		ejsMemoryError(ejs);
		return -1;
	}

	data = mprAlloc(ejs, MPR_BUFSIZE);
	if (buf == 0) {
		mprFree(buf);
		ejsMemoryError(ejs);
		return -1;
	}

	app = mprGetApp(ejs);
	file = mprOpen(ejs, argv[0]->string, O_RDONLY, 0664);
	if (file == 0) {
		ejsError(ejs, EJS_IO_ERROR, "Cant open %s", argv[0]->string);
		mprFree(buf);
		return -1;
	}

	rc = 0;
	while ((bytes = mprRead(file, data, MPR_BUFSIZE)) > 0) {
		if (mprPutBlockToBuf(buf, data, bytes) != bytes) {
			ejsError(ejs, EJS_IO_ERROR, "Write error to %s", argv[1]->string);
			rc = -1;
			break;
		}
	}

	ejsSetReturnValueToBinaryString(ejs, mprGetBufStart(buf), 
		mprGetBufLength(buf));

	mprClose(file);
	mprFree(data);
	mprFree(buf);

	return rc;
}

/******************************************************************************/
/*
 *	function void remove(string path);
 */

static int removeProc(Ejs *ejs, EjsVar *thisObj, int argc, EjsVar **argv)
{
	int		rc;

	if (argc != 1 || !ejsVarIsString(argv[0])) {
		ejsError(ejs, EJS_ARG_ERROR, "Bad usage: remove(path)");
		return -1;
	}

	rc = unlink(argv[0]->string);
	if (rc < 0) {
		ejsError(ejs, EJS_IO_ERROR, "Cant remove file");
		return -1;
	}
	return 0;
}

/******************************************************************************/
/*
 *	function void rename(string from, string to);
 */

static int renameProc(Ejs *ejs, EjsVar *thisObj, int argc, EjsVar **argv)
{
	int		rc;

	if (argc != 2 || !ejsVarIsString(argv[0]) || !ejsVarIsString(argv[1])) {
		ejsError(ejs, EJS_ARG_ERROR, "Bad usage: rename(old, new)");
		return -1;
	}

	unlink(argv[1]->string);
	rc = rename(argv[0]->string, argv[1]->string);
	if (rc < 0) {
		ejsError(ejs, EJS_IO_ERROR, "Cant rename file");
		return -1;
	}
	return 0;
}

/******************************************************************************/
/*
 *	function void copy(string old, string new);
 */

static int copyProc(Ejs *ejs, EjsVar *thisObj, int argc, EjsVar **argv)
{
	MprFile		*from, *to;
	char		*buf;
	int			bytes, rc;

	if (argc != 2 || !ejsVarIsString(argv[0]) || !ejsVarIsString(argv[1])) {
		ejsError(ejs, EJS_ARG_ERROR, "Bad usage: copy(old, new)");
		return -1;
	}

	buf = mprAlloc(ejs, MPR_BUFSIZE);
	if (buf == 0) {
		ejsMemoryError(ejs);
		return -1;
	}

	from = mprOpen(ejs, argv[0]->string, O_RDONLY | O_BINARY, 0664);
	if (from == 0) {
		ejsError(ejs, EJS_IO_ERROR, "Cant open %s", argv[0]->string);
		mprFree(buf);
		return -1;
	}

	to = mprOpen(ejs, argv[1]->string, O_CREAT | O_BINARY, 0664);
	if (to == 0) {
		ejsError(ejs, EJS_IO_ERROR, "Cant create %s", argv[1]->string);
		mprClose(from);
		mprFree(buf);
		return -1;
	}

	rc = 0;
	while ((bytes = mprRead(from, buf, MPR_BUFSIZE)) > 0) {
		if (mprWrite(to, buf, bytes) != bytes) {
			ejsError(ejs, EJS_IO_ERROR, "Write error to %s", argv[1]->string);
			rc = -1;
			break;
		}
	}

	mprClose(from);
	mprClose(to);
	mprFree(buf);

	return rc;
}

/******************************************************************************/
/*
 *	function FileInfo getFileInfo(string path);
 *
 *	MOB -- should create a real class FileInfo
 */

static int getFileInfoProc(Ejs *ejs, EjsVar *thisObj, int argc, EjsVar **argv)
{
	MprFileInfo	info;
	EjsVar		*fileInfo;
	int			rc;

	if (argc != 1 || !ejsVarIsString(argv[0])) {
		ejsError(ejs, EJS_ARG_ERROR, "Bad usage: getFileInfo(path)");
		return -1;
	}

	fileInfo = ejsCreateObjVar(ejs);
	if (fileInfo == 0) {
		ejsMemoryError(ejs);
		return -1;
	}
	ejsMakeObjPermanent(fileInfo, 1);

	rc = mprGetFileInfo(ejs, argv[0]->string, &info);
	if (rc < 0) {
		ejsMakeObjPermanent(fileInfo, 0);
		ejsFreeVar(ejs, fileInfo);
		ejsError(ejs, EJS_IO_ERROR, "Cant get file info for %s",
			argv[0]->string);
		return -1;
	}

	ejsSetPropertyToInteger(ejs, fileInfo, "created", info.ctime);
	ejsSetPropertyToInteger(ejs, fileInfo, "length", info.size);
	ejsSetPropertyToBoolean(ejs, fileInfo, "isDir", info.isDir);

	ejsSetReturnValue(ejs, fileInfo);
	ejsMakeObjPermanent(fileInfo, 0);

	return 0;
}

/******************************************************************************/
/******************************** Initialization ******************************/
/******************************************************************************/

int ejsDefineFileSystemClass(Ejs *ejs)
{
	EjsVar	*fileSystemClass;

	fileSystemClass = ejsDefineClass(ejs, "FileSystem", "Object", 0);
	if (fileSystemClass == 0) {
		return MPR_ERR_CANT_INITIALIZE;
	}

	/*
	 *	Define the methods
	 */
	ejsDefineCMethod(ejs, fileSystemClass, "access", accessProc, 0);
	ejsDefineCMethod(ejs, fileSystemClass, "mkdir", mkdirProc, 0);
	ejsDefineCMethod(ejs, fileSystemClass, "rmdir", rmdirProc, 0);
	ejsDefineCMethod(ejs, fileSystemClass, "dirList", dirListProc, 0);
	ejsDefineCMethod(ejs, fileSystemClass, "writeFile", writeFileProc, 0);
	ejsDefineCMethod(ejs, fileSystemClass, "readFile", readFileProc, 0);
	ejsDefineCMethod(ejs, fileSystemClass, "remove", removeProc, 0);
	ejsDefineCMethod(ejs, fileSystemClass, "rename", renameProc, 0);
	ejsDefineCMethod(ejs, fileSystemClass, "copy", copyProc, 0);
	ejsDefineCMethod(ejs, fileSystemClass, "getFileInfo", getFileInfoProc, 0);

	//	MOB -- should be a property with accessor
	ejsDefineCMethod(ejs, fileSystemClass, "getFreeSpace", getFreeSpaceProc, 0);

	return ejsObjHasErrors(fileSystemClass) ? MPR_ERR_CANT_INITIALIZE: 0;
}

/******************************************************************************/

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim:tw=78
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
