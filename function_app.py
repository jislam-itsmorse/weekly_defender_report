import azure.functions as func
from defender import main

app = func.FunctionApp()

# Runs every Friday at 10:00 AM UTC
# Cron format: seconds minutes hours day month day-of-week
@app.schedule(schedule="0 0 10 * * 5", arg_name="mytimer", run_on_startup=False, use_monitor=True)
def defender_report(mytimer: func.TimerRequest) -> None:
    import logging
    logging.info("Generating Defender report...")
    # Add your code to generate the Defender report here
    main()
    logging.info("Defender report generated successfully.") 