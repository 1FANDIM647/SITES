function search ( id= sss2 ) {

	search_line=promt( "администрация , программирование , книги   ");

    switch ( search_line ) {

      case администрация :
      load ("Администрирование1.html");
      break;
      case программирование :
      load ("Программирование1.html");
      break ;
      case книги :
      load("Книги1.html");
      break;

      default :

      console.log ( "Введите администрация или книги или программирование " );
      alert ( "Введите администрация или книги или программирование " );





    };
};








