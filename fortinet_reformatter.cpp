#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include "fortinet_reformatter.h"


void FortinetReformat::pkt(string file){
    std::ifstream input_file;
    input_file.open(file);

    if (!input_file) {
      std::cerr << "Could not open file" << std::endl;
    }  
    else
    {
      ofstream outputFile;
      outputFile.open("out.txt");
      
      for( string line; getline( input_file, line ); )
      {
        string substring = line.substr(0,1);
        string space (" ");
        if (space.compare(substring) != 0) {
            outputFile << line_reformat(line);
        }
        else{
          outputFile << line;
        }
      }
      
      outputFile.close();
    }
}

string FortinetReformat::line_reformat(string input_string){
      string x ("x");
      string date_pattern ("->");
      string time_stamp;
     
      long xpos = input_string.find(x);
      long datepos = input_string.find(date_pattern);

      if (xpos == -1 && datepos == -1) return input_string;

      if (datepos != -1) {
        time_stamp = "\n" + input_string.substr(0,26) + "\n";

        return time_stamp;
      }

      return pkt_line_reformat(input_string);
}


string FortinetReformat::pkt_line_reformat(string input){
    // takes out the '0x' in fortinet sniffer output, text2pcap expects the input
    // to start with a row of 4 numbers '0000', fortinet output is of the form '0x0000'
    // start input from position 2, bypassing the '0x' in a packet line
    string end_string = input.substr(2);

    long l = end_string.length();
    string space (" ");
    string p;
    std::vector<long> space_pos_vector;
    for(long i = 0;i < l; ++i){
        p = end_string[i];
        if ( p.compare(space) == 0  ){
          space_pos_vector.push_back(i);
        }
     }
     int vector_size = space_pos_vector.size();
     if (vector_size == 8){

       return full_pkt_line(end_string,space_pos_vector);
     }
     else{

       return trailing_line(end_string,space_pos_vector);
    }
}

string FortinetReformat::full_pkt_line(string line,vector<long>& space_pos_vector){

  size_t vector_size = space_pos_vector.size();
  if (vector_size == 0) return line;
  string returned_line = line.substr(0,4) + "   "; // initial address + 3 spaces

  long prior_space;
  string string_chunk;

  string space(" ");
  string first_byte_block;
  string second_byte_block;
  string corrected_block;

  for(int j =0;j < vector_size - 1 ; ++j){

    prior_space = space_pos_vector[j];
    string_chunk = line.substr(prior_space + 1, 4);
    isHex = is_hex_notation(string_chunk);

    if (string_chunk.length() == 4) {
      first_byte_block = string_chunk.substr(0,2);
      second_byte_block = string_chunk.substr(2,2);
      corrected_block = space + first_byte_block + space + second_byte_block;
      returned_line += corrected_block;
    }
  }

  long last_space = space_pos_vector.back();
  string last_chunk = line.substr( last_space + 1 );

  first_byte_block = last_chunk.substr(0,2);
  second_byte_block = last_chunk.substr(2,2);
  corrected_block = space + first_byte_block + space + second_byte_block;
  returned_line += corrected_block + "\n";

  return returned_line;
}

string FortinetReformat::trailing_line(string line,vector<long>& space_pos_vector){
  
  size_t vector_size = space_pos_vector.size();
  if (vector_size == 0) return line;
  
  string returned_line = line.substr(0,4) + "   "; // initial address + 3 spaces

  long prior_space;
  long next_space;
  long delta;

  string string_chunk;
  long string_chunk_length;
  string space(" ");
  string first_byte_block;
  string second_byte_block;
  string corrected_block;

  for(int j =0;j < vector_size - 1 ; ++j){

    prior_space = space_pos_vector[j];
    next_space = space_pos_vector[j + 1];
    delta = next_space - prior_space;
    string_chunk = line.substr(prior_space + 1, delta - 1 );
    string_chunk_length = string_chunk.length();

    if (string_chunk.length() == 4 ) {
      first_byte_block = string_chunk.substr(0,2);
      second_byte_block = string_chunk.substr(2,2);
      returned_line += space + first_byte_block + space + second_byte_block;
    }
    else if (string_chunk.length() == 2){
      first_byte_block = string_chunk.substr(0,2);
      returned_line += space + first_byte_block;;
    }
  }
  returned_line += "\n";

  return returned_line;
}
