import configuration
from mimecast.connection import Mimecast
import os
import time
from mimecast.logger import log, syslogger, write_file, read_file
from dateutil.parser import parse
from zipfile import ZipFile

# Declare the type of event we want to ingest
event_type = "/api/audit/get-siem-logs"
connection = Mimecast(event_type)
interval_time = configuration.logging_details["INTERVAL_TIMER"]


def init_directory():
  if not os.path.exists(configuration.logging_details["LOG_FILE_PATH"]):
    os.makedirs(configuration.logging_details["LOG_FILE_PATH"])

def send_file_to_syslog(filename):
  with open(filename, "r") as log_file:
    lines = log_file.read().splitlines()
    for line in lines:
      syslogger.info(line)

def get_mta_siem_logs(checkpoint_dir, base_url, access_key, secret_key):
  # Set checkpoint file name to store page token
  checkpoint_filename = os.path.join(checkpoint_dir, "get_mta_siem_logs_checkpoint")
  compression_enabled = configuration.logging_details["USE_COMPRESSION_WHERE_POSSIBLE"]

  # Build post body for request
  post_body = {
    "data": [{
      "type": "MTA",
      "compress": compression_enabled
    }]
  }

  if os.path.exists(checkpoint_filename):
    post_body["data"][0]["token"] = read_file(checkpoint_filename)

  # Send request to API
  resp = connection.post_request(
    base_url, event_type, post_body, access_key, secret_key
  )

  # Process response
  if resp != "error":
    resp_body = resp.text
    resp_headers = resp.headers
    resp_status = resp.status_code
    content_type = resp_headers["Content-Type"]

    if resp_status == 429:
      log.warn(
        "Rate limit hit. Sleeping for %s"
        % str(resp_headers["X-RateLimitReset"])
      )
      rate_limit = int(resp_headers["X-RateLimit-Reset"]) / 1000 % 60
      time.sleep(rate_limit * 20)

    # End if response is JSON as there is no log file to download
    if content_type == "application/json":
      log.info("No more SIEM logs available - Resting for 60 seconds")
      time.sleep(60)
      return True

    # Process log file
    elif content_type == "application/octet-stream":
      try:
        file_name = resp_headers["Content-Disposition"].split('="')
        file_name = file_name[1][:-1]
        file_name_end = file_name.split("_")[-1]

        file_date_dir = file_name_end.split(".")[0][0:8]
        full_dir = os.path.join(
          configuration.logging_details["LOG_FILE_PATH"], file_date_dir
        )

        if not os.path.exists(full_dir):
          os.makedirs(full_dir)

        # Save file to log file path
        full_log_path = os.path.join(full_dir, file_name)

        data_to_send = resp_body
        if(compression_enabled):
          data_to_send = resp

        ## ensure that file is written as binary if compression is enabled
        write_file(full_log_path, data_to_send, compression_enabled)
        file_ts = parse(file_date_dir).timestamp()
        os.utime(full_log_path, (file_ts, file_ts))

        # Save mc-siem-token page token to check point directory
        write_file(checkpoint_filename, resp_headers["mc-siem-token"])
        try:
          if configuration.syslog_details["syslog_output"] is True:
            log.info(
              "Loading file: %s to output to %s:%s" % (
                full_log_path,
                configuration.syslog_details["syslog_server"],
                str(configuration.syslog_details["syslog_port"])
              )
            )

            if(compression_enabled):
              with ZipFile(full_log_path) as zip:
                zip.extractall(path=full_dir)
                for name in zip.namelist():
                  send_file_to_syslog(name)
            else:
              send_file_to_syslog(full_log_path)

            log.info("Syslog output completed for file " + file_name)
        except Exception as e:
          log.error(
            "Unexpected error writing to syslog. Exception: " + str(e)
          )

        # return true to continue loop
        return True

      except Exception as e:
        return True   # continue loop

    else:
      # Handle errors
      log.error("Unexpected response")
      for header in resp_headers:
        log.error(header)
      return False


def get_siem_logs():
  try:
    base_url = connection.get_base_url(
      configuration.authentication_details["EMAIL_ADDRESS"]
    )
    print(base_url)
  except Exception:
    log.error(
      "Error discovering base url for %s. Please double check configuration.py"
      % (configuration.authentication_details["EMAIL_ADDRESS"])
    )
    quit()

  # Request log data in a loop until there are no more logs to collect
  try:
    log.info("Getting MTA log data")
    while (
      get_mta_siem_logs(
        checkpoint_dir=configuration.logging_details["CHK_POINT_DIR"],
        base_url=base_url,
        access_key=configuration.authentication_details["ACCESS_KEY"],
        secret_key=configuration.authentication_details["SECRET_KEY"],
      )
      is True
    ):
      log.info("Getting additional SIEM logs")
  except Exception as e:
    log.error("Unexpected error getting MTA logs " + (str(e)))
  quit()


init_directory()
get_siem_logs()
