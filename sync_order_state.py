#!/usr/bin/env python
import os
from app import create_app, db, models

if __name__ == "__main__":
    app = create_app(os.getenv('LEO_CONFIG') or 'default')
    app.app_context().push()
    models.OperationRecord.sync_souplus_orders()