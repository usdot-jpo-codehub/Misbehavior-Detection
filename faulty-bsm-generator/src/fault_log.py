'''
utils.py

lesser utility functions to avoid overcrowding main /src/ scripts
'''
from constants import OUTPUT_DIR, LOG_NAME
from os import path
import csv


class FaultLog:
    def __init__(self):
        self.cur_id = self.read_log()

    
    '''
    def read_log

    reads CSV file to count current id of new faulty-bsm
    '''
    def read_log(self):
        cur_id = 0

        log_path = path.join(OUTPUT_DIR, LOG_NAME)
        # check if log exists
        try:
            file = open(log_path, 'r')
            log_reader = csv.reader(file)
            for row in log_reader: cur_id += 1
        except: 
            print("No log found --- creating.")
            file = open(log_path, 'a+')
            log_writer = csv.writer(file)
            log_writer.writerow(['bsm_id', 'fault_id', 'fault_desc', 'date'])
        return cur_id

    '''
    def assign_id

    return an id and icrement internal id 
        ....
    '''
    def assign_id(self):
        cur_id = self.cur_id
        self.cur_id = cur_id + 1
        return cur_id


    '''
    def write_to_log

    provided list of log rows, write them to file. The log format should take the form of 
        timestamp (float), id (int), misbehavior_type (int),
        ....
    '''
    def write_to_log(self, items):
        log_path = path.join(OUTPUT_DIR, LOG_NAME)
        
        with open(log_path, 'a+') as file:
            log_writer = csv.writer(file)
            log_writer.writerow(items)
        file.close()
