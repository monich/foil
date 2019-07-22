# Microsoft Developer Studio Project File - Name="libfoil" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=libfoil - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "libfoil.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "libfoil.mak" CFG="libfoil - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "libfoil - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "libfoil - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "libfoil - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "build/Release"
# PROP Intermediate_Dir "build/Release"
# PROP Target_Dir ""
F90=df.exe
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "include" /I "src" /I "$(LIBGLIBUTIL_DIR)/include" /I "$(GTK_ROOT)/include/glib-2.0" /I "$(GTK_ROOT)/lib/glib-2.0/include" /I "$(OPENSSL_ROOT)/include" /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /YX /FD /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ELSEIF  "$(CFG)" == "libfoil - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "build/Debug"
# PROP Intermediate_Dir "build/Debug"
# PROP Target_Dir ""
F90=df.exe
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /YX /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /Zi /Od /I "include" /I "src" /I "$(LIBGLIBUTIL_DIR)/include" /I "$(GTK_ROOT)/include/glib-2.0" /I "$(GTK_ROOT)/lib/glib-2.0/include" /I "$(OPENSSL_ROOT)/include" /D "WIN32" /D "_DEBUG" /D "DEBUG" /D "_MBCS" /D "_LIB" /FR /FD /GZ /c
# SUBTRACT CPP /YX
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ENDIF 

# Begin Target

# Name "libfoil - Win32 Release"
# Name "libfoil - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\src\foil_asn1.c
# End Source File
# Begin Source File

SOURCE=.\src\foil_cipher.c
# End Source File
# Begin Source File

SOURCE=.\src\foil_cipher_aes.c
# End Source File
# Begin Source File

SOURCE=.\src\foil_cipher_sync.c
# End Source File
# Begin Source File

SOURCE=.\src\foil_cmac.c
# End Source File
# Begin Source File

SOURCE=.\src\foil_digest.c
# End Source File
# Begin Source File

SOURCE=.\src\foil_digest_md5.c
# End Source File
# Begin Source File

SOURCE=.\src\foil_digest_sha1.c
# End Source File
# Begin Source File

SOURCE=.\src\foil_digest_sha256.c
# End Source File
# Begin Source File

SOURCE=.\src\foil_hmac.c
# End Source File
# Begin Source File

SOURCE=.\src\foil_input.c
# End Source File
# Begin Source File

SOURCE=.\src\foil_input_base64.c
# End Source File
# Begin Source File

SOURCE=.\src\foil_input_cipher.c
# End Source File
# Begin Source File

SOURCE=.\src\foil_input_digest.c
# End Source File
# Begin Source File

SOURCE=.\src\foil_input_file.c
# End Source File
# Begin Source File

SOURCE=.\src\foil_input_mem.c
# End Source File
# Begin Source File

SOURCE=.\src\foil_input_range.c
# End Source File
# Begin Source File

SOURCE=.\src\foil_key.c
# End Source File
# Begin Source File

SOURCE=.\src\foil_key_aes.c
# End Source File
# Begin Source File

SOURCE=.\src\foil_key_des.c
# End Source File
# Begin Source File

SOURCE=.\src\foil_key_rsa_private.c
# End Source File
# Begin Source File

SOURCE=.\src\foil_key_rsa_public.c
# End Source File
# Begin Source File

SOURCE=.\src\openssl\foil_openssl_rsa.c
# End Source File
# Begin Source File

SOURCE=.\src\foil_output.c
# End Source File
# Begin Source File

SOURCE=.\src\foil_output_base64.c
# End Source File
# Begin Source File

SOURCE=.\src\foil_output_digest.c
# End Source File
# Begin Source File

SOURCE=.\src\foil_output_file.c
# End Source File
# Begin Source File

SOURCE=.\src\foil_output_mem.c
# End Source File
# Begin Source File

SOURCE=.\src\foil_pool.c
# End Source File
# Begin Source File

SOURCE=.\src\foil_private_key.c
# End Source File
# Begin Source File

SOURCE=.\src\foil_random.c
# End Source File
# Begin Source File

SOURCE=.\src\foil_sign.c
# End Source File
# Begin Source File

SOURCE=.\src\foil_util.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=.\include\foil_asn1.h
# End Source File
# Begin Source File

SOURCE=.\include\foil_cipher.h
# End Source File
# Begin Source File

SOURCE=.\include\foil_cmac.h
# End Source File
# Begin Source File

SOURCE=.\include\foil_digest.h
# End Source File
# Begin Source File

SOURCE=.\include\foil_hmac.h
# End Source File
# Begin Source File

SOURCE=.\include\foil_input.h
# End Source File
# Begin Source File

SOURCE=.\include\foil_key.h
# End Source File
# Begin Source File

SOURCE=.\include\foil_log.h
# End Source File
# Begin Source File

SOURCE=.\include\foil_output.h
# End Source File
# Begin Source File

SOURCE=.\include\foil_private_key.h
# End Source File
# Begin Source File

SOURCE=.\include\foil_random.h
# End Source File
# Begin Source File

SOURCE=.\include\foil_sign.h
# End Source File
# Begin Source File

SOURCE=.\include\foil_types.h
# End Source File
# Begin Source File

SOURCE=.\include\foil_util.h
# End Source File
# End Group
# Begin Group "Internal Header Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\src\foil_asn1_p.h
# End Source File
# Begin Source File

SOURCE=.\src\foil_cipher_aes.h
# End Source File
# Begin Source File

SOURCE=.\src\foil_cipher_p.h
# End Source File
# Begin Source File

SOURCE=.\src\foil_cipher_sync.h
# End Source File
# Begin Source File

SOURCE=.\src\foil_digest_p.h
# End Source File
# Begin Source File

SOURCE=.\src\foil_input_p.h
# End Source File
# Begin Source File

SOURCE=.\src\foil_key_aes.h
# End Source File
# Begin Source File

SOURCE=.\src\foil_key_des_p.h
# End Source File
# Begin Source File

SOURCE=.\src\foil_key_p.h
# End Source File
# Begin Source File

SOURCE=.\src\foil_key_rsa_private.h
# End Source File
# Begin Source File

SOURCE=.\src\foil_key_rsa_public.h
# End Source File
# Begin Source File

SOURCE=.\src\foil_log_p.h
# End Source File
# Begin Source File

SOURCE=.\src\foil_oid.h
# End Source File
# Begin Source File

SOURCE=.\src\foil_output_p.h
# End Source File
# Begin Source File

SOURCE=.\src\foil_pool.h
# End Source File
# Begin Source File

SOURCE=.\src\foil_private_key_p.h
# End Source File
# Begin Source File

SOURCE=.\src\foil_random_p.h
# End Source File
# Begin Source File

SOURCE=.\src\foil_types_p.h
# End Source File
# Begin Source File

SOURCE=.\src\foil_util_p.h
# End Source File
# End Group
# Begin Group "Openssl Source Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\src\openssl\foil_openssl_cipher_aes_cbc_decrypt.c
# End Source File
# Begin Source File

SOURCE=.\src\openssl\foil_openssl_cipher_aes_cbc_encrypt.c
# End Source File
# Begin Source File

SOURCE=.\src\openssl\foil_openssl_cipher_des_cbc.c
# End Source File
# Begin Source File

SOURCE=.\src\openssl\foil_openssl_cipher_rsa.c
# End Source File
# Begin Source File

SOURCE=.\src\openssl\foil_openssl_cipher_rsa_decrypt.c
# End Source File
# Begin Source File

SOURCE=.\src\openssl\foil_openssl_cipher_rsa_encrypt.c
# End Source File
# Begin Source File

SOURCE=.\src\openssl\foil_openssl_digest_md5.c
# End Source File
# Begin Source File

SOURCE=.\src\openssl\foil_openssl_digest_sha1.c
# End Source File
# Begin Source File

SOURCE=.\src\openssl\foil_openssl_digest_sha256.c
# End Source File
# Begin Source File

SOURCE=.\src\openssl\foil_openssl_key_des.c
# End Source File
# Begin Source File

SOURCE=.\src\openssl\foil_openssl_key_rsa_private.c
# End Source File
# Begin Source File

SOURCE=.\src\openssl\foil_openssl_key_rsa_public.c
# End Source File
# Begin Source File

SOURCE=.\src\openssl\foil_openssl_random.c
# End Source File
# End Group
# Begin Group "Openssl Header Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\src\openssl\foil_openssl_des.h
# End Source File
# Begin Source File

SOURCE=.\src\openssl\foil_openssl_random.hcp 
# End Source File
# Begin Source File

SOURCE=.\src\openssl\foil_openssl_rsa.h
# End Source File
# End Group
# Begin Source File

SOURCE=.\libfoil.pc.in
# End Source File
# Begin Source File

SOURCE=..\LICENSE
# End Source File
# Begin Source File

SOURCE=.\Makefile
# End Source File
# Begin Source File

SOURCE=..\README
# End Source File
# Begin Source File

SOURCE=..\VERSION
# End Source File
# End Target
# End Project
