import os
import sys
from dotenv import load_dotenv
load_dotenv()
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uvicorn
from loguru import logger
if __name__ == '__main__':
    logger.info('Starting ClaudioSec...')
    uvicorn.run('api.main:app', host='0.0.0.0', port=8000, reload=False)
