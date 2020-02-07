var mySwiper = new Swiper('.swiper-container', {
    slidesPerView : 2,
    loop: true,
    navigation : {
        nextEl : '.arrow',
     
    },
});

var menuButton = document.querySelector('menu-button');
var menu = document.querySelector('.header');
menuButton.addEventListener('click',function(){
      menuButton.classList.toggle('menu-button-active');
      menuButton.classList.toggle('header-active');
});