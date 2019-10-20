#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <GNU>
#include <ctype.h>
#include <assert.h>
#include <math.h>
#include <limits.h>
#include <stdarg.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <time.h>
#include <threads.h>
#include <fenv.h>
#include <wchar.h>
#include <iso646.h>
#include <uchar.h>
#include <stdalign.h>
#include <stdatomic.h>
#include <float.h>
#include <inttypes.h>
#include <signal.h>
#include <wchar.h>
#include <errno.h>
// we will create  few functions for  my the libery (dok.h)







double electron_energy1 ( ) {

system("chcp 1251>nul");

double m=9.1E-31;//  WE ARE MULTING 10 IN -31 OF  DEGREE 

double c=2.998E8;

double energy,b;  // Variables  for writing down of energy 

int n=10,k; 

printf("Speed v/c\tEnergy (Dj)\n" );

// Calculating value of electron 

for (k=0; k<n;k++){


	b=(double)k/n;

	energy=m*c*c*(1/sqrt(1-b*b)-1);


	printf("\t%.1f\t%\n",b,energy); 

   

}

 system ("pause>null");

return m ,c  ;
}

double electron_energy2 ( double m1  ) {

system("chcp 1251>nul");

double c=2.998E8;

double energy,b;  // Variables  for writing down of energy 

int n=10,k; 

printf("Speed v/c\tEnergy (Dj)\n" );

// Calculating value of electron 

for (k=0; k<n;k++){


	b=(double)k/n;

	energy=m1*c*c*(1/sqrt(1-b*b)-1);


	printf("\t%.1f\t%\n",b,energy); 

   

}

 system ("pause>null")

return c ;
}

int deg_of_two() {

  int pwr [n]; // We  are creating  array 
   
  pwr[0] =1;
  
  printf("|%d|",pwr[0]); 

  int k=1;

  while(k<n) {

     pwr[k]=pwr[k-1]*2;

     printf("%d|", pwr[k]);

     k++;
  }

  printf("\n");

  return n;

 system ("pause>null")

}



double squre_equation (double a, double b , double c ) {  // First function for my libery is  squre_equation 

  printf(" Enter  by first  'a' after 'b' after 'c' ");
  
  double D; double x1; double x2;

  D=b*b-4*a*c; 

  double x1=(-b-sqrt(D))/2*a;

  double x2=(-b+sqrt(D))/2*a;

  printf(" Your answer : "x1,x2);  

 system ("pause>null")
     
  return D;

 

}

char FAMIALIAS( char  sec_name ) {

 switch(sec_name){


  case Shishov:

   printf(" Programmer in Florida %s\n");

   printf(" Jew   %s\n", );
   printf(" height 174 cm  %s\n", );
   printf("he is good man %s\n", );
   break;
}

return 0;
}  


int  Calculating_of_income_by_diposit (int sum , int time_of_income) {

  
printf("Enter summ ");

printf("Enter income ");  

// procent bet 

double r=8,5;


int k=1; 

double s=1; // variable for  answer 

 // Calculating of result 
while (k<=time_of_income) {


s*=(1+r/100);

k++;




}
printf("Sum of income (per day):\t%.2f\n",sum);
printf("Procent bet (procent ):\t%.2f\n",r);
printf("Income (in day):\t%.2f\n",sum*(s-1));
printf("Income (in procent):\t%.2f\n",100*(s-1));

return r;
}




 int ct (void) {

  long int ttime;

  ttime=time(NULL); //Couting time 

  printf("Time :%s\n", ctime (&ttime) );




  return 0; 
 }








int main (void ) {
 
  ct () ;

   signed char  function ;

   if (function==electron_energy1){

   electron_energy1();
   }
  
   if (function==electron_energy2) {

     printf("Enter value of electron - m ");
     
     electron_energy2();


   } 

   if (function==degree_of_two){

    printf("Enter any  number");
    degree_of_two();

   }
   
   if (function==squre_equation){
   
   printf("Enter a , b , c for calculating of squre_equation");
   
   squre_equation();

   }

   
if(function==Calculating_of_income_by_diposit){
     
      Calculating_of_income_by_diposit();
   }

   if (function=FAMIALIAS) {

   	FAMIALIAS();
   
    printf("while is only Shishov");
   }

   return 0; 
  system ("pause>null")

}




























































