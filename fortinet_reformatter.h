#include <iostream>
#include <fstream>
#include <string>
#include <vector>


#ifndef FORTINET_REFORMATTER_H_INCLUDED
#define FORTINET_REFORMATTER_H_INCLUDED

using namespace std;


class FortinetReformat 
{

    public:
        FortinetReformat();

    private:
        void pkt(string);
        string pkt_line_reformat(string);
        string line_reformat(string);
        string full_pkt_line(string,vector<long>& space_pos_vector);
        string trailing_line(string,vector<long>& space_pos_vector);


};

#endif