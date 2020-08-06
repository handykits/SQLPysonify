import sys
sys.path.append('../')
import mysql.connector as mysql
import json
#modules
from main import settings
#separate logging for db and log
from main.models.db.dblogger import logger as dblog
from main.utils.logging import logger as log
import main.utils.id_generator as id_gen


#db configuration strings
__dbHost = settings.dbhost
__dbUser = settings.dbuser
__dbPass = settings.dbpass
__dbName = settings.dbname

def testConnection():
    db = mysql.connect(
      host = __dbHost,
      user = __dbUser,
      passwd = __dbPass,
      database = __dbName
      )
    cursor = db.cursor()
    query = "SELECT * FROM keywords"
    try:
        cursor.execute(query)
        records = cursor.fetchall()
        print("DB Test Was Successful")
    except Exception as e:
        print("FAIL CONNECTING TO DB!")
    finally:
        cursor.close()


#All database queries must be done by creating an object of the query class
#Query.process filter must be called before calling Query.go
#After query.go, call query.results to get the JSON formatted result

class Query():
    def __init__(self,secret = 0):
        #USAGE: new Query(1)
        #setParameters(__param) - to set the type,query and value manually
        #go() - send the query
        #Query.result - get JSON formatted result
        #secret param tells wether query should be logged or not (1 or 0)
        self.secret = secret
        #set query parameters
        self.type = "" #SQL Query types
        self.query = "" #parameterized query
        self.values = "" #query values tuple
        #set the reslt to default empty values this will then be changed after caling query.go
        self.result = {"count":"null","status":"","context":{}}
        self.query_id = id_gen.generate(10)#create a query id that to track the query transaction
        log.info("Successfully created a new Query Object with ID: {}".format(self.query_id))
        dblog.info("Successfully created a new Query Object with ID: {}".format(self.query_id))
        #When query is called, open a connection to DB
        

    def setParameters(self,__param):
        #USAGE:
        #{"type" :"INSERT",
        #"rows":"100" #for SELECT MANY size
        # "query" : "INSERT INTO (domain_id, domain_name,host) VALUES (%s,%s,%s)",
        # "values": ("1234","CSM ATL","core125")}
        #You can call this method to set all values at once by sending JSON
        #You can also set params one by one by calling class properties
        self.type = __param['type']
        self.query = __param['query']
        self.values = __param['values']
        if(self.secret == 0):
            log.debug("qid: {0} - Set query type to {1}.".format(self.query_id,self.type))
            log.debug("qid: {0} - Set query string to {1}.".format(self.query_id,self.query))
            log.debug("qid: {0} - Set query values to {1}.".format(self.query_id,self.values))
        log.info("qid: {0} parameters was successfully set with type: {1}".format(self.query_id,self.type))

    #for custom queries, you can set the parameters indivisually
    def setType(self,qtype):
        self.type = qtype
        log.debug("qid: {0} - Set query type to {1}.".format(self.query_id,self.type))

    def setQuery(self,query):
        #WARNING - DO NOT Ever concatenate user input and send here unless well sanitized
        #If you wish to add user input, use the query.generator function instead.
        self.query = query
        if(self.secret == 0):
            log.debug("qid: {0} - Set query string to {1}.".format(self.query_id,self.query))

    def setValues(self,values):
        self.values = values
        if(self.secret == 0):
            log.debug("qid: {0} - Set query values to {1}.".format(self.query_id,self.values))

    def __IDU(self):
        #private function for INSERT, UPDATE and DELETE Statements
        log.info("Initiating IDU query: {}".format(self.query_id))
        if(self.secret == 0):
            dblog.info("qid: {0} - Query: {1}".format(self.query_id,self.query))
            dblog.info("qid: {0} - Values: {1}".format(self.query_id,self.values))
        for retries in range(0,10): #Max of 10 retries. If query fails, send a critical error. else, break the loop
            try:
                __con = mysql.connect(
                        host = settings.dbhost,
                        user = settings.dbuser,
                        passwd = settings.dbpass,
                        database = settings.dbname
                    )
                __cursor = __con.cursor(prepared=True)
                __cursor.execute(self.query,self.values)
                log.debug("qid: {0} successfully sent query to db".format(self.query_id))
                __con.commit()
                log.debug("qid: {0} successfully commited query to db".format(self.query_id))
                __cursor.close()
                dblog.info("qid: {0}. successfully closed query connection to db".format(self.query_id))
                #set result values
                self.result['status'] = "success"
                self.result['context'] = "Request proccessed."
                break
            except mysql.Error as error:
                dblog.error("qid: {0} Error: Unable to perform query".format(self.query_id))
                log.error("qid: {0} Error: Unable to perform query".format(self.query_id))
                if(self.secret == 0):
                    dblog.error("qid: {0} Error: Unable to perform query with error: {1}".format(self.query_id,error))
                    log.error("qid: {0} Error: Unable to perform query with error: {1}".format(self.query_id,error))
                #if error is due to duplicate entry, break the loop and return the error
                if(error.errno == 1062):
                    dblog.error("qid: {0} Error: Duplicate Values for Primary key".format(self.query_id))
                    log.error("qid: {0} Error: Duplicate Values for Primary key".format(self.query_id))
                    #set result value
                    self.result['context'] = "Duplicate Entry Found."
                    break
                else:
                    continue
            finally:
                __con.commit()
                __cursor.close()

    def __select(self):
        #private function for Select Statements
        log.info("Initiating SELECT query: {}".format(self.query_id))
        if(self.secret == 0):
            dblog.info("qid: {0} - Query: {1}".format(self.query_id,self.query))
            dblog.info("qid: {0} - Values: {1}".format(self.query_id,self.values))
        for retries in range(0,10): #Max of 10 retries. If query fails, send a critical error. else, break the loop
            try:
                __con = mysql.connect(
                        host = settings.dbhost,
                        user = settings.dbuser,
                        passwd = settings.dbpass,
                        database = settings.dbname
                    )
                __cursor = __con.cursor(prepared=True)
                __cursor.execute(self.query,self.values)
                log.debug("qid: {0} successfully sent SELECT query to db".format(self.query_id))
                log.debug("qid: {0} Retrieving Query Results".format(self.query_id))
                r = __cursor.fetchmany(100)
                log.debug("qid: {0} Constructing result Array for JSON construction".format(self.query_id))
                arr = [] #array for results for JSON construction of self.result.context
                for row in r:
                    record = dict(zip(__cursor.column_names, row))
                    arr.append(record)
                #send result to JSON parsing function
                self.__parseResult(arr) #the function will also set the value for self.result
                #set result values
                self.result['status'] = "success"
                __con.close()
                __cursor.close()
                dblog.info("qid: {0}. successfully closed query connection to db".format(self.query_id))
                break
            except mysql.Error as error:
                dblog.error("qid: {0} Error: Unable to perform query".format(self.query_id))
                log.error("qid: {0} Error: Unable to perform query".format(self.query_id))
                if(self.secret == 0):
                    dblog.error("qid: {0} Error: Unable to perform query with error: {1}".format(self.query_id,error))
                    log.error("qid: {0} Error: Unable to perform query with error: {1}".format(self.query_id,error))
                #if error is due to duplicate entry, break the loop and return the error
                if(error.errno == 1062):
                    dblog.error("qid: {0} Error: Duplicate Values for Primary key".format(self.query_id))
                    log.error("qid: {0} Error: Duplicate Values for Primary key".format(self.query_id))
                    self.result['context'] = "Duplicate Entry Found."
                    break
                else:
                    continue
            finally:
                __cursor.close()
    
    def __parseResult(self,__queryResult):
        #convert SQL result to JSON
        items = __queryResult
        log.info("qid: {} - Received SELECT Query result from DB. Parsing result to JSON".format(self.query_id))
        try:
            a = json.dumps(items,indent=4, sort_keys=True, default=str) #CREATE JSON
            formattedResult = json.loads(a)
            log.info("qid: {} - Successfully converted to JSON.Setting query object result to formatted result".format(self.query_id))
            self.result['context'] = formattedResult
            self.result['count'] =  str(len(formattedResult))
            log.debug("qid: {0} - Records found = {1}. Status = {2}".format(self.query_id,self.result["count"],self.result["status"]))
            #log.debug("Output: {}".format(self.result))
        except Exception as e:
            log.exception("qid: {0} - unable to parse result: {1}".format(self.query_id,e))

    def go(self):
        #Make sure that all queries are sanitized
        if(self.__sanitizeXss(self.values) == True):
            if(self.type == "INSERT" or self.type == "DELETE" or self.type == "UPDATE"):
                self.__IDU()
            if(self.type == "SELECT"):
                self.__select()
        else: #throw exception for unsanitized value
            log.error("qid: {} - input contains un-allowed characters".format(self.query_id))
            self.result['status'] = "failed"
            if(self.result['context'] == "" or self.result['context'] == None):
                self.result['context'] = "Unable to process request. Make sure the operation is valid."
            #raise Exception("input contains un-allowed characters. DB query aborted")


    #class methods for generating queris and making sure that querys are valid
    #use these methods when creating generic querys. for more specific queries, use the SETxx methods to set the class properties manually
    def generate(self,__param):
        #USAGE- use this to generate queries from complex filters. 
        #The function does not include INSERT Statement as Insert Statement is straight forward which we can easily sanitize
        #the function will call __setparams after generating the query and you can manually call Query.go
        #Sample
        # __param = {
	    # "type": "UPDATE",
        # "table": "case_from_sf",
        # "filter": [{
    	# "col": "keyword",
		# "operator": "=",
        # "comp" : "",
	    # "value": "xxxxx"	    	
        #     },
	    # {
	    # 	"col": "user",
	    # 	"operator": "=",
        #   "comp":"AND",
	    # 	"value": "xxxxx"
	    # 	}
	    # ],
	    # "set": [
	    # 	{
	    # 		"col": "count",
	    # 		"value": "farm"
	    # 	}
	    # ]
        # }
        base_query = ""
        q_type = ""
        proceed = self.__checkIfProceedGenerator(__param)
        if(proceed == True):
            #Step 1 - Set the BASE Query
            base_query = self.__createBaseQuery(__param)

            #Step 2 - set the where clause
            filters = __param['filter']
            where_clause = ""
            values = ()
            where_clause = self.__createWhereClause(filters)
            
            #Step 3 - Combine the base query and where clause to form a new base query
            base_query = base_query + " " + where_clause
            log.info("qid: {0} - Base query Constructed: {1}".format(self.query_id,base_query))

            #Step 4 - Now we have a base query, we will populate a tuple to complete the parameterized query
            values = self.__populateTuple(__param)
            #Step 5 - create the QUERY class properties
            q = {"type":__param["type"],"query":base_query,"values":values}
            self.setParameters(q)
            if(self.secret == 0):
                log.info("qid: {0} - Query Constructed: {1}".format(self.query_id,q))
            

    def __createBaseQuery(self,__param):
         #Set the BASE Query depending on query type
            if(__param['type'] == "SELECT"):
                base_query = "SELECT * FROM {}".format(__param['table'])
            elif(__param['type'] == "UPDATE"):
                set_clause = self.__processSetColumns(__param['set'])
                base_query = "UPDATE {0} {1}".format(__param['table'], set_clause)
                q_type = "UPDATE"
            elif(__param['type'] == "DELETE"):
                base_query = "DELETE FROM {}".format(__param['table'])
                q_type = "DELETE"
            return base_query

    def __createWhereClause(self,filters):
            i = 0
            for filter in filters:
                #loop through filters and construct the query. NOTE no column and operators are direct user input
                if(self.secret != 1):
                    log.info("qid: {0} - proccessing filters: {1}".format(self.query_id,filter))
                else:
                    log.info("qid: {0} - proccessing filters".format(self.query_id))
                if(i < 1):
                    where_clause = "where {0} {1} {2} %s".format(filter['comp'],filter['col'],filter['operator'])
                else:
                    if(filter['col'] == "comparison"):#some filters are complicated that it needs mutiple conditions. 
                    #I chose to add a dummy column name to indicate that the entry is for comparison pharentesis position only
                        where_clause = "{0} {1}".format(where_clause,filter['comp'])
                    else:
                        where_clause = "{0} {1} {2} {3} %s".format(where_clause,filter['comp'],filter['col'],filter['operator'])
                i = i + 1
            return where_clause

    def __checkIfProceedGenerator(self,__param):
        #START of FUNCTION
        #columns cannot be parameterized so I decided to check columns in an overkilled way.
        #columns, operators, and comparisons should not come directly from Users
        proceed = True #place holder wether to proceed or not for query
        try:
            if(self.__checkColumns(__param['filter'])):
                #make sure that types are valid type
                valid_types = ["SELECT","UPDATE","INSERT","DELETE"]
                if __param['type'] in valid_types:
                    proceed = True
                    log.info("qid: {0} - Query.checkIfProceedGen - Query type is Valid".format(self.query_id))
            else:
                proceed = False
                return proceed # columnn is not valid
            #for Update query, check the set columns
            if(__param['type'] == "UPDATE"):
                log.info("qid: {0} - Query.checkifProceedGen - Checking if Set columns declared are valid".format(self.query_id))
                columns_valid = self.__checkColumns(__param['set'])

                if(columns_valid == False):
                    proceed = False
                    return proceed
                log.info("qid: {0} - Query.checkifProceedGen - Set Columns are valid".format(self.query_id))
            #make sure query is sanitized:
            log.info("qid: {0} - Query.checkifProceedGen - Checking if Query filters are sanitized".format(self.query_id))
            if(self._sanitizeQuery(__param['filter']) != True):
                proceed = False
                log.info("qid: {0} - Query.checkifProceedGen - Query is not an acceptable Query based on Sanitazion Rules".format(self.query_id))
                return proceed
        except Exception as e:
            log.error("qid: {0} -checkIfProceed Unable to generate query due to exception: {1}".format(self.query_id,e))
            proceed = False
            print(e)
        return proceed

    def __checkColumns(self,cols):
        #OVERKILL, it's up to you to validate columns
        #send the filter to this function first to check if the column is a valid column
        #we do this because we cannot parameterize a column and we allow users to customize a column filter
        #in short, user can only filter based on existing columns.
        #TODO check if there is anyway to get it from .env file via settings.py
        columns = ("behavior_id","behavior_name","related_host","domain_id","domain_name","data_center","current_host","host_issue","domain_entry_id","token","disabled",
                    "current_db","current_pop","current_nas","sccws_server","fvs_fgv","entry_id","snapshot","report_id","domain_id","user_id","timestamp","behaviors",
                    "si_number","description","snapshot_time","sf_id","case_number","service","topic","status","subject","status","time_opened","si_number","phase",
                    "keyword","user","type","count","comparison")
        valid = True
        for col in cols:
            cleaned_Col = col['col'].replace("(","")
            cleaned_Col = cleaned_Col.replace(")","") #For mutiple conditions that uses pharenthesis
            log.debug("qid: {0} - Query.checkColumns - Validating {1}".format(self.query_id,col['col']))
            if cleaned_Col not in columns:
                valid = False
                log.error("qid: {0} - Query.checkColumns invalid column name for {1}".format(self.query_id,cleaned_Col))
        return valid


    def __populateTuple(self,__param):
        #populate tuple for parameterized Query
        #send the ['filter'] here to loop through each filter and create a tuple for values
        filters = __param['filter']
        values = ()
        #cast tuple to list temporarily to add items
        l = list(values)
        if(__param['type'] == "UPDATE"): #Update query has the values inside the set
            sets = __param['set']
            i = 0
            for set in sets:
                l.append(set['value'])

        for filter in filters:
            #loop through filters and constuct the tuple for a paremeterized request
            if(filter['col'] != "comparison"): #Do not add dummy comparison entry as they are only for comparison purpose
                l.append(filter['value'])
        values = tuple(l)
        if(self.secret != 1):
            log.info("qid: {0} - successfully constructed values for query: {1}".format(self.query_id,values))
        else:
            log.info("qid: {0} - successfully constructed values for query.".format(self.query_id))
        return values

    def __processSetColumns(self,__columns):
        #SET methods has a columns and values inside SET key. 
        #{"set":[
        #   {"col":"behavior_id","value":"dehc7z"},
        #   {"col":"behavior_id","value":"dehc7z"}
        #   ]}
        base_clause = "SET "
        i = 0
        for column in __columns:
            if( i < 1):
                base_clause = "{0} {1} = %s".format(base_clause,column['col'])
            else:
                base_clause = "{0}, {1} = %s".format(base_clause,column['col'])
            i = i + 1  
        log.info("qid: {0} - constucted SET clause: {1}".format(self.query_id,base_clause)) 
        return base_clause

    def _sanitizeQuery(self,__filters):
        __sanitized = False
        log.debug("qid: {0} - Started sanitizing queries".format(self.query_id))
        if(self.__sanitizeOperators(__filters) == True and self.__sanitizeComparison(__filters) == True):
            __sanitized = True
            log.info("qid: {0} - Successfully Sanitized the Query and Query is Valid")
        else:
            print(self.__sanitizeComparison(__filters))
            log.error("qid {0} - Query does not fit Sanitation rule.".format(self.query_id))
        return __sanitized
        
    def __sanitizeComparison(self,__filters):
        sanitized_comp = True
        allowed_comparisons = ("AND", "OR", "NOT", "AND NOT", "OR NOT" , "","AND")
        for filter in __filters:
            #For multiple conditions that uses pharentesis, ex: AND x = 1 OR (a = 2 AND b =2 )
            cleaned_filter = filter['comp'].replace(")", "")
            cleaned_filter = cleaned_filter.replace("(", "") 
            if(cleaned_filter in allowed_comparisons):
                log.info("qid: {0} - {1} is a valid comparison string".format(self.query_id,filter["comp"]))
            else:
                sanitized_comp = False
                print(cleaned_filter)
        log.info("qid: {0} - Sanitized Comparisons: {1}".format(self.query_id,sanitized_comp))
        return sanitized_comp


    def __sanitizeOperators(self,__filters):
        sanitized_ops = True
        allowed_operators = ("=", "ALL" ,"ANY", "BETWEEN" , "EXISTS", "IN","LIKE", "NOT", "OR" , "SOME", ">", "<", ">=", "<=", "<>","")
        log.info("qid: {0} - Query - sanitizeOperators - Starting to check if operators are valid".format(self.query_id))
        for filter in __filters:
            cleaned_filter = filter['operator'].replace(")", "") #For multiple conditions that uses pharentesisr
            if(cleaned_filter not in allowed_operators):
                sanitized_ops = False
                log.info("qid: {0} - Operators {1} is invalid".format(self.query_id,cleaned_filter))
            else:
                log.info("qid: {0} - Sanitized Operator: {1} is valid".format(self.query_id,cleaned_filter))
        return sanitized_ops

    def __sanitizeXss(self,values):
        #TODO create a more robust xss sanitation and also get it from settings.py
        log.info("qid: {0} - Query.SanitizeXss Started Sanitizing Query for XSS".format(self.query_id))
        if (any('>' in i for i in values)) :
            print("ghhh")
            log.error("qid: {0} unaccepted values.XSS protection: Character: {1} is not allowed.".format(self.query_id,str(values)))
            self.result['context'] = "Unable to save un-allowed characters"
            return False
        else:
            return True
