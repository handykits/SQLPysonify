#packages
import time #To test function that needs sleep
#model modules
from models.db import query as db

#test db connection
db.testConnection()

#test select
def testSelect():
    a = db.Query(secret = 1)
    params = {"type":"SELECT","query":"SELECT distinct keyword FROM keywords GROUP BY keyword","values":""}
    a.setParameters(params)
    try:
        a.go()
        result = a.result
        if(int(result['count']) >= 1):
            print("TEST 1: Successful in performing test SELECT query")
        else:
            print("TEST 1: ERROR in SELECT query")
    except Exception as e:
        print("TEST 1: ERROR in SELECT query {}".format(e))
testSelect()

#Test INSERT
def testInsert():
    a = db.Query(secret = 1)
    params = {"type":"INSERT","query":"INSERT INTO keywords (keyword,type) VALUES (%s,%s);","values":("testkeyword","test")}
    a.setParameters(params)
    try:
        a.go()
        print("TEST 2: Successful in performing test INSERT query")
    except Exception as e:
        print("TEST 2: ERROR in INSERT query {}".format(e))
testInsert()

#Test UPDATE
def testUpdate():
    a = db.Query(secret = 1)
    params = {"type":"UPDATE","query":"UPDATE keywords SET count = %s WHERE keyword = %s;","values":("5","testkeyword")}
    a.setParameters(params)
    try:
        a.go()
        print("TEST 2: Successful in performing test UPDATE query")
    except Exception as e:
        print("TEST 2: ERROR in UPDATE query {}".format(e))
testUpdate()

#Test DELETE
def testDelete():
    a = db.Query(secret = 1)
    params = {"type":"DELETE","query":"DELETE FROM keywords WHERE keyword = %s;","values":("testkeyword",)}
    a.setParameters(params)
    try:
        a.go()
        print("TEST 3: Successful in performing test DELETE query")
    except Exception as e:
        print("TEST 3: ERROR in DELETE query {}".format(e))
testDelete()


#JSON to SQL consturctir
#NOTE: Query(1) means it's a sensitive information query that should not be logged.
#Query() means it's a query that can be logged
def testSelectQueryGenerator():
    __param = {
	    "type": "SELECT",
        "table": "keywords",
        "filter": [{
        	"col": "keyword",
		    "operator": "=",
            "comp" : "(",
	        "value": "dropped"	    	
            },
	        {
	        "col": "user",
	        "operator": "=",
            "comp":"AND",
	        "value": "jgutierrez"
	    	},
	        {
	        "col": "keyword",
	        "operator": "=",
            "comp":")OR(",
	        "value": "dialing"
	    	},
	        {
	        "col": "user",
	        "operator": "=",
            "comp":"AND",
	        "value": "jgutierrez"
	    	},
            {
	        "col": "user",
	        "operator": "=",
            "comp":"AND",
	        "value": "jgutierrez"
	    	},{
	        "col": "comparison",
	        "operator": "",
            "comp":")",
	        "value": ""
	    	} 
    	    ]
        }
    a = db.Query(secret = 1)
    a.generate(__param)
    #If you wish to edit the query, you can easily do the following.
    #Example, adding limit - DO NOT EVER add user input and concatenate them here. This is intended for Query options only
    #IE - DESC, LIMIT, etc
    #a.setQuery("{0} LIMIT 1".format(a.query))
    try:
        a.go()
        print("Test 4: Successfully performed SELECT query generator")
    except Exception as e:
        print("Test 4 Error in performing query for select query generator {e}".format(e))
    

testSelectQueryGenerator()

def testUpdateQueryGenerator():
    #create a test record first for update
    a = db.Query()
    params = {"type":"INSERT","query":"INSERT INTO keywords (keyword,type) VALUES (%s,%s);","values":("testkeyword","test")}
    a.setParameters(params)
    a.go()
    __param = {
	    "type": "UPDATE",
        "table": "keywords",
        "filter": [{
        	"col": "keyword",
		    "operator": "=",
            "comp" : "",
	        "value": "testkeyword"	    	
            },
	        {
	        "col": "type",
	        "operator": "=",
            "comp":"AND",
	        "value": "test"
	    	}
    	    ],
        "set":[
            {
            "col":"count", #column to update
            "value":"10" #new value
        }
        ]
        }
    #update test record    
    a.generate(__param)
    a.go()
    #nowe test wether the value was actually updated
    b = db.Query(secret = 1)
    params = {"type":"SELECT","query":"SELECT * FROM keywords WHERE keyword = %s","values":("testkeyword",)}
    b.setParameters(params)
    try:
        b.go()
        if(int(b.result['context'][0]['count']) == 10):
            print("TEST 5: Successful in updating the record using Query Generator")
        else:
            print("TEST 5: The record was not successfully updated")
    except Exception as e:
        print("TEST 5: ERROR in SELECT query generator {}".format(e))
    
testUpdateQueryGenerator()

def testDeleteQueryGenerator():
    __param = {
	    "type": "DELETE",
        "table": "keywords",
        "filter": [{
        	"col": "keyword",
		    "operator": "=",
            "comp" : "",
	        "value": "testkeyword"	    	
            },
	        {
	        "col": "type",
	        "operator": "=",
            "comp":"AND",
	        "value": "test"
	    	}
    	    ]
        }
    a = db.Query(secret = 1)
    a.generate(__param)
    #If you wish to edit the query, you can easily do the following.
    #Example, adding limit - DO NOT EVER add user input and concatenate them here. This is intended for Query options only
    #IE - DESC, LIMIT, etc
    #a.setQuery("{0} LIMIT 1".format(a.query))
    try:
        a.go()
        print("Test 6: Successfully performed DELETE query generator")
    except Exception as e:
        print("Test 6 Error in performing query for DELETE query generator {e}".format(e))

testDeleteQueryGenerator()
