//
//  main.cpp
//  nslookups
//
//  Created by Joshua Engelsma on 2/26/16.
//  Copyright © 2016 Joshua Engelsma. All rights reserved.
//

#include <iostream>
#include <thread>
#include <string>
#include <cstdio>
#include <memory>
#include <vector>


using namespace std;
vector<string> results(10);

string exec(const char* cmd) {
    shared_ptr<FILE> pipe(popen(cmd, "r"), pclose);
    if (!pipe) return "ERROR";
    char buffer[128];
    string result = "";
    while (!feof(pipe.get())) {
        if (fgets(buffer, 128, pipe.get()) != NULL)
            result += buffer;
    }
    return result;
}

void isValidDomain(string domain, int threadNum){
    string cmd = "nslookup " + domain;
    if(domain[0] == '-'){
        results[threadNum - 1] = "** server can't find when you include -";
        return;
    }
    string result = exec(cmd.c_str());
    
    results[threadNum - 1] = result;
}

int main(int argc, const char * argv[]) {
    // insert code here...
    if (argc < 4){
        cout << "Invalid number of args passed. Expected 10, but found " << argc - 1 << endl;
        return 1;
    }
    thread t1(isValidDomain, argv[1], 1);
    thread t2(isValidDomain, argv[2], 2);
    thread t3(isValidDomain, argv[3], 3);
    thread t4(isValidDomain, argv[4], 4);
    thread t5(isValidDomain, argv[5], 5);
    thread t6(isValidDomain, argv[6], 6);
    thread t7(isValidDomain, argv[7], 7);
    thread t8(isValidDomain, argv[8], 8);
    thread t9(isValidDomain, argv[9], 9);
    thread t10(isValidDomain, argv[10], 10);
    
    t1.join();
    t2.join();
    t3.join();
    t4.join();
    t5.join();
    t6.join();
    t7.join();
    t8.join();
    t9.join();
    t10.join();
    
    string printStr = "";
    //run through and verify the results
    for(int i = 0; i < 10; i++){
        string result = results[i];
        size_t found = result.find("** server can't find");
        size_t found2 = result.find("*** Can't find");
        string finalResult =  found != string::npos || found2 != string::npos ? "F" : "T";
        printStr += i == 9 ? finalResult : finalResult + ",";
    }
    
    cout << printStr << endl;
    
    return 0;
}
