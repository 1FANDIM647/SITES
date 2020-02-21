
// object for  calculator  
const DATA = {
    whichSite: ['landing','multiPage', 'onlineStore'],
    price: [4000,8000,26000],
    desktopTemplates: [50 , 40 , 30],
    adapt: 20,
    mobileTemplates:15,
    editable: 10,
    metrikaYandex: [500,1000,2000],
    analyticsGoogle: [850,1350,3000],
    sendOrder: 500,
    deadlineDay: [ [2,7] , [3,10], [7,14]],
    deadlinePercent: [20 ,17,15]
};

// how  to talk   with elements of html code 

// we got element "start-button "
const startButton = document.querySelector('.start-button'),
firstScreen = document.querySelector('.first-screen'), 
mainForm = document.querySelector('.main-form'),
formCalculate = document.querySelector('.form-calculate'),
endButton =document.querySelector('.end-button'),
total =document.querySelector('.total'),
fastRange = document.querySelector('.fast-range'),
totalPriceSum = document.querySelector('.total_price__sum'),
adapt_phone=document.querySelector(".checkbox-label adapt_value"),
mobile_desighn = document.querySelector(".checkbox-label mobileTemplates_value");
// if  we do not need adaptation for cell phones ,  than  we do not need desigh(HOMEWORK2)
function Blockadapt(adapt_phone){
     
   if(adapt_phone === true) {
      hideElem(mobile_desighn);
   } 
  
}
 


function showElem(elem) {
    
    elem.style.display = 'block';  
}

function hideElem(elem) {
    
    elem.style.display = 'none';  
}

function priceCalculation(elem){
 let result = 0,
     index=0; 
     options = [];

    if (elem.name === 'whichSite'){
        for(const item of formCalculate.elements){
             if(item.type === 'checkbox'){
                 item.checked = false;
             }
        }
        hideElem(fastRange);
    }
     
    for (const item of formCalculate.elements){
          if (item.name === 'whichSite' && item.checked){
              // get index each element
              index = (DATA.whichSite.indexOf(item.value));
          } else if (item.classList.contains('calc-handler') && item.checked ){
              options.push(item.value)
          }      
    }
    options.forEach(function(key){
       if (typeof(DATA[key])=== 'number'){
           if(key === 'sendOrder'){
               result+= data[key]
           }
           else {
               result += DATA.price[index] * DATA[key]/100
           }
       }
       else {
            if (key === 'desktopTemplates'){
                 result += DATA.price[index] * DATA[key][index] / 100

            }else{
                result += DATA[key][index];
            }
       }
       
    })

    result += DATA.price[index];
    // in begin  result will be 0 
    totalPriceSum.textContent = result;
}



function handlerCallBackForm(event){
    const target = event.target;
    
    // if element contains 
    if (target.classList.contains('want-faster')) {
        if ( target.checked) {
            showElem(fastRange);
        } 
        else {
            hideElem(fastRange);
        }
        
       
    } 
    if (target.classList.contains('calc-handler')){
        priceCalculation(target);
    }
};

startButton.addEventListener('click', function() {
    showElem(mainForm);// we show  main part of site
    hideElem(firstScreen);
 });

endButton.addEventListener('click', function() {
    for ( const elem of formCalculate.elements){
        if (elem.tagName === 'FIELDSET'){
            hideElem(elem);
        }
    }
    showElem(total); 

});

formCalculate.addEventListener('change', handlerCallBackForm); 