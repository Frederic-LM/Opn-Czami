# ftp_manager.py

import ftplib
import logging
from pathlib import Path

class FTPManager:
    """Handles all FTP/FTPS communications for the application."""
    def test_connection(self, host: str, user: str, password: str) -> str:
        """Tests the FTP connection with the given credentials."""
        if not all([host, user, password]):
            return "Host, User, and Password cannot be empty."
        try:
            with ftplib.FTP_TLS(timeout=10) as ftp:
                ftp.connect(host)
                ftp.login(user, password)
                ftp.prot_p()
                ftp.voidcmd("NOOP")
            return "Success"
        except ftplib.all_errors as e:
            return f"FTP Test Failed: {e}"
        except Exception as e:
            return f"An unexpected error occurred: {e}"

    def upload_file(self, local_path: Path, remote_dir: str, remote_filename: str, ftp_settings: dict) -> str:
        """Uploads a single file, creating the remote directory structure if it doesn't exist."""
        host, user, password = ftp_settings.get("host"), ftp_settings.get("user"), ftp_settings.get("password")
        if not all([host, user, password, remote_dir]):
            return "FTP settings are incomplete."
        
        logging.info(f"FTP: Attempting to upload '{local_path.name}' to remote dir '{remote_dir}'")
        try:
            with ftplib.FTP_TLS(timeout=15) as ftp:
                ftp.connect(host)
                ftp.login(user, password)
                ftp.prot_p()
                path_parts = Path(remote_dir.strip("/\\")).parts
                for part in path_parts:
                    if not part or part in ('/', '\\'): continue
                    try:
                        ftp.cwd(part)
                    except ftplib.error_perm:
                        logging.info(f"FTP: Directory '{part}' not found, attempting to create.")
                        try:
                            ftp.mkd(part)
                            ftp.cwd(part)
                        except ftplib.error_perm as mkd_e:
                            err_msg = f"FTP Error: Failed to create or access directory '{part}'. Check permissions. Error: {mkd_e}"
                            logging.error(err_msg)
                            return err_msg
                
                logging.info(f"FTP: Now in target directory. Uploading '{remote_filename}'...")
                with local_path.open("rb") as f:
                    ftp.storbinary(f"STOR {remote_filename}", f)

            success_msg = f"Successfully uploaded {remote_filename} to {remote_dir}."
            logging.info(success_msg)
            return success_msg
        except ftplib.all_errors as e:
            err_msg = f"FTP Upload Error: {e}"
            logging.error(err_msg, exc_info=True)
            return err_msg
        except Exception as e:
            err_msg = f"An unexpected error occurred during upload: {e}"
            logging.error(err_msg, exc_info=True)
            return err_msg
